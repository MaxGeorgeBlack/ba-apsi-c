#include "ba.h"

#include <openssl/obj_mac.h>
#include <string.h>

void ba_ec_init(ba_ec *e) {
    e->group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    e->ctx = BN_CTX_new();
    e->order = BN_new();
    ba_require(e->group && e->ctx && e->order, "EC allocation");
    ba_require(EC_GROUP_check(e->group, e->ctx) == 1, "P-256 group validation");
    ba_require(EC_GROUP_get_order(e->group, e->order, e->ctx) == 1, "EC order");

    BIGNUM *h = BN_new();
    ba_require(h != NULL, "cofactor allocation");
    ba_require(EC_GROUP_get_cofactor(e->group, h, e->ctx) == 1 && BN_is_one(h),
               "cofactor must be 1");
    BN_free(h);
}

void ba_ec_clear(ba_ec *e) {
    EC_GROUP_free(e->group);
    BN_CTX_free(e->ctx);
    BN_free(e->order);
    memset(e, 0, sizeof *e);
}

BIGNUM *ba_bn_u64(uint64_t n) {
    unsigned char b[8];
    ba_u64be(b, n);
    BIGNUM *r = BN_bin2bn(b, 8, NULL);
    ba_require(r != NULL, "BN conversion");
    return r;
}

void ba_ec_mul_i64(ba_ec *e, EC_POINT *out, int64_t n) {
    uint64_t v = n < 0 ? (uint64_t)(-(n + 1)) + 1 : (uint64_t)n;
    BIGNUM *b = ba_bn_u64(v);

    ba_require(EC_POINT_mul(e->group, out, b, NULL, NULL, e->ctx) == 1, "EC scalar multiply");
    if (n < 0)
        ba_require(EC_POINT_invert(e->group, out, e->ctx) == 1, "EC negate");

    BN_free(b);
}

void ba_ec_encode(ba_ec *e, const EC_POINT *p, unsigned char out[33]) {
    memset(out, 0, 33);
    if (EC_POINT_is_at_infinity(e->group, p))
        return;
    ba_require(EC_POINT_point2oct(e->group, p, POINT_CONVERSION_COMPRESSED, out, 33, e->ctx) == 33,
               "point encode");
}

ba_status ba_ec_decode(ba_ec *e, EC_POINT *p, const unsigned char in[33]) {
    if (in[0] == 0) {
        unsigned v = 0;
        for (size_t i = 1; i < 33; i++)
            v |= in[i];
        if (v)
            return BA_INVALID;
        ba_require(EC_POINT_set_to_infinity(e->group, p) == 1, "set identity");
        return BA_OK;
    }

    if (in[0] != 2 && in[0] != 3)
        return BA_INVALID;
    if (EC_POINT_oct2point(e->group, p, in, 33, e->ctx) != 1 ||
        EC_POINT_is_on_curve(e->group, p, e->ctx) != 1)
        return BA_INVALID;

    /* P-256 has cofactor 1: every on-curve point belongs to the prime-order group. */
    unsigned char canonical[33];
    ba_ec_encode(e, p, canonical);
    return memcmp(in, canonical, 33) ? BA_INVALID : BA_OK;
}

void ba_encrypt_with_coin(
    ba_ec *e, const EC_POINT *pk, uint64_t v, const BIGNUM *r, ba_ciphertext *out) {
    EC_POINT *a = EC_POINT_new(e->group), *b = EC_POINT_new(e->group), *m = EC_POINT_new(e->group);
    BIGNUM *value = ba_bn_u64(v);
    ba_require(a && b && m, "encryption allocation");
    ba_require(!BN_is_negative(r) && BN_cmp(r, e->order) < 0, "encryption coin range");

    ba_require(EC_POINT_mul(e->group, a, r, NULL, NULL, e->ctx) == 1, "encrypt rG");
    ba_require(EC_POINT_mul(e->group, b, NULL, pk, r, e->ctx) == 1, "encrypt rPK");
    ba_require(EC_POINT_mul(e->group, m, value, NULL, NULL, e->ctx) == 1, "encrypt vG");
    ba_require(EC_POINT_add(e->group, b, b, m, e->ctx) == 1, "encrypt sum");

    ba_ec_encode(e, a, out->bytes);
    ba_ec_encode(e, b, out->bytes + 33);

    EC_POINT_free(a);
    EC_POINT_free(b);
    EC_POINT_free(m);
    BN_clear_free(value);
}

void ba_encrypt(ba_ec *e, const EC_POINT *pk, uint64_t v, ba_ciphertext *out) {
    BIGNUM *r = BN_new();
    ba_require(r != NULL, "encryption randomness");
    ba_require(BN_priv_rand_range(r, e->order) == 1, "encryption random sampling");
    BN_set_flags(r, BN_FLG_CONSTTIME);
    ba_encrypt_with_coin(e, pk, v, r, out);
    BN_clear_free(r);
}

ba_status ba_decrypt_point(ba_ec *e, const BIGNUM *sk, const ba_ciphertext *ct, EC_POINT *out) {
    EC_POINT *a = EC_POINT_new(e->group), *b = EC_POINT_new(e->group);
    ba_require(a && b, "decryption allocation");

    ba_status status = BA_INVALID;
    if (ba_ec_decode(e, a, ct->bytes) != BA_OK || ba_ec_decode(e, b, ct->bytes + 33) != BA_OK)
        goto end;

    ba_require(EC_POINT_mul(e->group, a, NULL, a, sk, e->ctx) == 1, "decrypt skC1");
    ba_require(EC_POINT_invert(e->group, a, e->ctx) == 1, "decrypt negate");
    ba_require(EC_POINT_add(e->group, out, b, a, e->ctx) == 1, "decrypt subtract");
    status = BA_OK;

end:

    EC_POINT_free(a);
    EC_POINT_free(b);
    return status;
}
