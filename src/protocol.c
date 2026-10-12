#include "ba.h"

#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static void nz(element_t x) {
    do {
        element_random(x);
    } while (element_is0(x));
}

static void digest_update(EVP_MD_CTX *c, const void *p, size_t n) {
    ba_require(EVP_DigestUpdate(c, p, n) == 1, "public fingerprint");
}

static void digest_element(EVP_MD_CTX *c, element_t x) {
    size_t n = (size_t)element_length_in_bytes(x);
    unsigned char *buf = ba_alloc(n, 1), len[8];
    ba_require(element_to_bytes(buf, x) == (int)n, "pairing encode");
    ba_u64be(len, n);
    digest_update(c, len, 8);
    digest_update(c, buf, n);
    free(buf);
}

static ba_status distinct(ba_public *p, const uint64_t *ids, size_t n, size_t capacity) {
    if (n > capacity || (n && !ids))
        return BA_INVALID;

    ba_table t;
    ba_status status = ba_table_init(&t, n, 8, SIZE_MAX);
    if (status != BA_OK)
        return status;

    for (size_t i = 0; i < n; i++) {
        if (ids[i] == 0 || ids[i] > p->cfg.universe) {
            status = BA_INVALID;
            break;
        }
        unsigned char k[8];
        ba_u64be(k, ids[i]);
        size_t slot = ba_table_find(&t, k);
        if (t.count[slot]) {
            status = BA_DUPLICATE;
            break;
        }
        ba_table_insert(&t, k, i);
    }

    ba_table_clear(&t);
    return status;
}

static char *read_params(const char *file) {
    FILE *f = fopen(file, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }

    long n = ftell(f);
    if (n < 1 || n > 1024 * 1024 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }

    char *s = ba_alloc((size_t)n + 1, 1);
    size_t got = fread(s, 1, (size_t)n, f);
    fclose(f);
    if (got != (size_t)n) {
        free(s);
        return NULL;
    }
    return s;
}

static int param_integer(mpz_t out, const char *s, const char *name) {
    char key[32];
    int len = snprintf(key, sizeof key, "\n%s ", name);
    const char *v = strstr(s, key);
    if (!v)
        return 0;

    v += len;
    const char *end = strchr(v, '\n');
    size_t n = end ? (size_t)(end - v) : strlen(v);
    char *t = ba_alloc(n + 1, 1);
    memcpy(t, v, n);
    int ok = mpz_set_str(out, t, 10) == 0;
    free(t);
    return ok;
}

static int valid_params(const char *s) {
    if (strncmp(s, "type a\n", 7) != 0 && strncmp(s, "type a\r\n", 8) != 0)
        return 0;

    mpz_t q, r, h, tmp;
    mpz_inits(q, r, h, tmp, NULL);
    int ok = 0;
    if (!param_integer(q, s, "q") || !param_integer(r, s, "r") || !param_integer(h, s, "h"))
        goto end;
    if (mpz_sizeinbase(r, 2) < 160 || mpz_sizeinbase(q, 2) < 512 || mpz_sgn(h) <= 0)
        goto end;
    if (!mpz_probab_prime_p(q, 32) || !mpz_probab_prime_p(r, 32) || mpz_fdiv_ui(q, 4) != 3)
        goto end;

    mpz_mul(tmp, h, r);
    mpz_sub_ui(tmp, tmp, 1);
    ok = mpz_cmp(q, tmp) == 0;

end:
    mpz_clears(q, r, h, tmp, NULL);
    return ok;
}

ba_status ba_setup(
    ba_public *p, ba_authority *a, ba_recoverer *r, const char *params, const ba_config *cfg) {
    memset(p, 0, sizeof *p);
    memset(a, 0, sizeof *a);
    memset(r, 0, sizeof *r);
    if (!cfg->universe || cfg->universe > INT_MAX || !cfg->nc || !cfg->ns || !cfg->degree ||
        cfg->degree > 1024 || cfg->max_value > (uint64_t)INT64_MAX - 1 ||
        cfg->nc > ((uint64_t)INT64_MAX - 1) / (cfg->max_value ? cfg->max_value : 1))
        return BA_INVALID;

    char *text = read_params(params);
    if (!text)
        return BA_INVALID;
    if (!valid_params(text)) {
        free(text);
        return BA_INVALID;
    }
    if (pairing_init_set_str(p->pairing, text) != 0) {
        free(text);
        return BA_INVALID;
    }
    if (!pairing_is_symmetric(p->pairing)) {
        pairing_clear(p->pairing);
        free(text);
        return BA_INVALID;
    }

    p->cfg = *cfg;
    p->cfg.bound = (uint64_t)cfg->nc * cfg->max_value;
    element_init_G1(p->g, p->pairing);
    element_init_GT(p->Y, p->pairing);
    do {
        element_random(p->g);
    } while (element_is1(p->g));

    p->T = ba_alloc(cfg->universe, sizeof(element_t));
    a->t = ba_alloc(cfg->universe, sizeof(element_t));
    a->coeff = ba_alloc(cfg->degree, sizeof(element_t));
    a->universe = cfg->universe;
    a->degree = cfg->degree;
    for (size_t i = 0; i < a->degree; i++) {
        element_init_Zr(a->coeff[i], p->pairing);
        if (i == 0)
            nz(a->coeff[i]);
        else
            element_random(a->coeff[i]);
    }

    element_pp_t fixed_base;
    element_pp_init(fixed_base, p->g);

    for (size_t i = 0; i < a->universe; i++) {
        element_init_Zr(a->t[i], p->pairing);
        nz(a->t[i]);
        element_init_G1(p->T[i], p->pairing);
        element_pp_pow_zn(p->T[i], a->t[i], fixed_base);
    }

    element_pp_clear(fixed_base);

    pairing_apply(p->Y, p->g, p->g, p->pairing);
    ba_require(!element_is1(p->Y), "nondegenerate generator");
    element_pow_zn(p->Y, p->Y, a->coeff[0]);

    ba_ec_init(&p->ec);
    r->sk = BN_new();
    p->pk = EC_POINT_new(p->ec.group);
    ba_require(r->sk && p->pk, "key allocation");
    do {
        ba_require(BN_priv_rand_range(r->sk, p->ec.order) == 1, "key generation");
    } while (BN_is_zero(r->sk));
    BN_set_flags(r->sk, BN_FLG_CONSTTIME);
    ba_require(EC_POINT_mul(p->ec.group, p->pk, r->sk, NULL, NULL, p->ec.ctx) == 1, "public key");

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    ba_require(md != NULL, "fingerprint allocation");
    ba_require(EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1, "fingerprint init");
    const char *suite = "BA-APSI-v1/PBC-Type-A/P-256/HKDF-SHA256";
    digest_update(md, suite, strlen(suite));
    digest_update(md, text, strlen(text));

    uint64_t config[] = {
        cfg->universe, cfg->nc, cfg->ns, cfg->degree, cfg->max_value, p->cfg.bound};
    unsigned char bytes[33];
    for (size_t i = 0; i < 6; i++) {
        ba_u64be(bytes, config[i]);
        digest_update(md, bytes, 8);
    }

    digest_element(md, p->g);
    digest_element(md, p->Y);
    for (size_t i = 0; i < cfg->universe; i++)
        digest_element(md, p->T[i]);
    ba_ec_encode(&p->ec, p->pk, bytes);
    digest_update(md, bytes, 33);
    unsigned outlen;
    ba_require(EVP_DigestFinal_ex(md, p->period, &outlen) == 1 && outlen == 32,
               "fingerprint final");

    EVP_MD_CTX_free(md);
    free(text);
    p->active = 1;
    return BA_OK;
}

void ba_setup_clear(ba_public *p, ba_authority *a, ba_recoverer *r) {
    if (!p->active)
        return;

    for (size_t i = 0; i < a->universe; i++) {
        element_clear(a->t[i]);
        element_clear(p->T[i]);
    }
    for (size_t i = 0; i < a->degree; i++)
        element_clear(a->coeff[i]);

    free(a->t);
    free(a->coeff);
    free(p->T);
    element_clear(p->g);
    element_clear(p->Y);
    pairing_clear(p->pairing);

    BN_clear_free(r->sk);
    EC_POINT_free(p->pk);
    ba_ec_clear(&p->ec);
    memset(p, 0, sizeof *p);
    memset(a, 0, sizeof *a);
    memset(r, 0, sizeof *r);
}

ba_status ba_authorize(ba_public *p,
                       ba_authority *a,
                       const uint64_t *ids,
                       size_t n,
                       ba_policy policy,
                       void *arg,
                       ba_certificates *out) {
    memset(out, 0, sizeof *out);
    ba_status status = distinct(p, ids, n, p->cfg.universe);
    if (status != BA_OK)
        return status;
    if (!policy)
        return BA_INVALID;
    for (size_t i = 0; i < n; i++)
        if (!policy(ids[i], arg))
            return BA_INVALID;

    out->n = n;
    out->ids = ba_alloc(n, sizeof(uint64_t));
    out->sigma = ba_alloc(n, sizeof(element_t));
    memcpy(out->period, p->period, 32);

    element_t x, v, inv;
    element_init_Zr(x, p->pairing);
    element_init_Zr(v, p->pairing);
    element_init_Zr(inv, p->pairing);

    element_pp_t fixed_base;
    element_pp_init(fixed_base, p->g);

    for (size_t i = 0; i < n; i++) {
        out->ids[i] = ids[i];
        element_set_si(x, (signed long)ids[i]);
        element_set(v, a->coeff[a->degree - 1]);
        for (size_t h = a->degree - 1; h > 0; h--) {
            element_mul(v, v, x);
            element_add(v, v, a->coeff[h - 1]);
        }
        element_invert(inv, a->t[ids[i] - 1]);
        element_mul(v, v, inv);
        element_init_G1(out->sigma[i], p->pairing);
        /* g^0 is the identity. Avoid the zero-exponent allocation leak in
         * this PBC version's default precomputed exponentiation path. */
        if (element_is0(v))
            element_set1(out->sigma[i]);
        else
            element_pp_pow_zn(out->sigma[i], v, fixed_base);
    }

    element_pp_clear(fixed_base);
    element_clear(x);
    element_clear(v);
    element_clear(inv);
    return BA_OK;
}

void ba_certificates_clear(ba_certificates *s) {
    for (size_t i = 0; i < s->n; i++)
        element_clear(s->sigma[i]);

    free(s->sigma);
    free(s->ids);
    memset(s, 0, sizeof *s);
}

void ba_context(ba_public *p,
                const char *client,
                const char *server,
                const unsigned char session[32],
                unsigned char out[32]) {
    unsigned char identities[32], bound[32], both[64];
    ba_digest("BA-APSI/roles/v1", client, strlen(client), server, strlen(server), identities);

    memcpy(both, p->period, 32);
    memcpy(both + 32, identities, 32);
    ba_digest("BA-APSI/context/v1", both, 64, session, 32, bound);
    memcpy(out, bound, 32);
}

static void hash_context(element_t h, const unsigned char ctx[32]) {
    unsigned char d[32];
    ba_digest("BA-APSI/Ht/PBC-Type-A/v1", ctx, 32, NULL, 0, d);
    element_from_hash(h, d, 32);
}

void ba_client_begin(ba_public *p, const unsigned char ctx[32], ba_request *r) {
    memset(r, 0, sizeof *r);
    element_init_Zr(r->x, p->pairing);
    element_init_G1(r->rc, p->pairing);
    nz(r->x);

    element_pow_zn(r->rc, p->g, r->x);
    memcpy(r->context, ctx, 32);
    r->active = 1;
}

void ba_request_clear(ba_request *r) {
    if (r->active) {
        element_clear(r->x);
        element_clear(r->rc);
    }
    memset(r, 0, sizeof *r);
}

static int valid_g1(ba_public *p, element_t v) {
    if (element_is1(v))
        return 0;

    element_t t;
    element_init_G1(t, p->pairing);
    element_pow_mpz(t, v, p->pairing->r);
    int ok = element_is1(t);
    element_clear(t);
    return ok;
}

static int valid_gt(ba_public *p, element_t v) {
    element_t t;
    element_init_GT(t, p->pairing);
    element_pow_mpz(t, v, p->pairing->r);
    int ok = element_is1(t);
    element_clear(t);
    return ok;
}

ba_status ba_server_respond(ba_public *p,
                            ba_certificates *s,
                            ba_request *r,
                            const unsigned char ctx[32],
                            int optimized,
                            ba_response *out) {
    memset(out, 0, sizeof *out);
    if (memcmp(s->period, p->period, 32) || memcmp(r->context, ctx, 32) || !valid_g1(p, r->rc))
        return BA_INVALID;

    ba_status status = distinct(p, s->ids, s->n, p->cfg.ns);
    if (status != BA_OK)
        return status;

    out->n = s->n;
    out->P = ba_alloc(s->n, sizeof(element_t));
    out->source = ba_alloc(s->n, sizeof(size_t));

    element_t y, h, f;
    element_init_Zr(y, p->pairing);
    element_init_G1(h, p->pairing);
    element_init_GT(f, p->pairing);
    element_init_G1(out->rs, p->pairing);
    nz(y);
    element_pow_zn(out->rs, p->g, y);
    hash_context(h, ctx);
    pairing_apply(f, r->rc, h, p->pairing);
    element_pow_zn(f, f, y);

    for (size_t i = 0; i < s->n; i++)
        out->source[i] = i;
    for (size_t i = s->n; i > 1; i--) {
        size_t j = (size_t)ba_random_below(i), tmp = out->source[i - 1];
        out->source[i - 1] = out->source[j];
        out->source[j] = tmp;
    }

    pairing_pp_t pp;
    if (optimized)
        pairing_pp_init(pp, out->rs, p->pairing);
    for (size_t j = 0; j < s->n; j++) {
        element_init_GT(out->P[j], p->pairing);
        if (optimized)
            pairing_pp_apply(out->P[j], s->sigma[out->source[j]], pp);
        else {
            pairing_apply(out->P[j], p->g, s->sigma[out->source[j]], p->pairing);
            element_pow_zn(out->P[j], out->P[j], y);
        }
        element_mul(out->P[j], out->P[j], f);
    }
    if (optimized)
        pairing_pp_clear(pp);
    element_clear(y);
    element_clear(h);
    element_clear(f);

    memcpy(out->context, ctx, 32);
    out->active = 1;
    return BA_OK;
}

void ba_response_clear(ba_response *r) {
    if (r->active) {
        for (size_t i = 0; i < r->n; i++)
            element_clear(r->P[i]);
        element_clear(r->rs);
    }

    free(r->P);
    free(r->source);
    memset(r, 0, sizeof *r);
}

ba_status ba_client_match(ba_public *p,
                          ba_certificates *c,
                          ba_request *r,
                          ba_response *s,
                          int optimized,
                          ba_matches *out) {
    memset(out, 0, sizeof *out);
    if (memcmp(c->period, p->period, 32) || memcmp(r->context, s->context, 32) ||
        s->n > p->cfg.ns || !valid_g1(p, s->rs))
        return BA_INVALID;

    ba_status status = distinct(p, c->ids, c->n, p->cfg.nc);
    if (status != BA_OK)
        return status;
    for (size_t j = 0; j < s->n; j++)
        if (!valid_gt(p, s->P[j]))
            return BA_INVALID;

    size_t bytes = (size_t)pairing_length_in_bytes_GT(p->pairing);
    unsigned char *key = ba_alloc(bytes, 1);
    ba_table table;
    status = ba_table_init(&table, s->n, bytes, SIZE_MAX);
    if (status != BA_OK) {
        free(key);
        return status;
    }
    for (size_t j = 0; j < s->n; j++) {
        ba_require(element_to_bytes(key, s->P[j]) == (int)bytes, "GT serialize");
        ba_table_insert(&table, key, j);
    }

    unsigned char *used = ba_alloc(s->n, 1);
    out->items = ba_alloc(c->n, sizeof(ba_match));
    out->token_bytes = bytes;
    memcpy(out->context, r->context, 32);

    element_t h, z, token;
    element_init_G1(h, p->pairing);
    element_init_G1(z, p->pairing);
    element_init_GT(token, p->pairing);
    hash_context(h, r->context);
    element_pow_zn(h, h, r->x);

    pairing_pp_t pp;
    if (optimized)
        pairing_pp_init(pp, s->rs, p->pairing);

    for (size_t i = 0; i < c->n; i++) {
        element_mul(z, c->sigma[i], h);
        if (optimized)
            pairing_pp_apply(token, z, pp);
        else
            pairing_apply(token, s->rs, z, p->pairing);
        ba_require(element_to_bytes(key, token) == (int)bytes, "GT serialize");
        size_t slot = ba_table_find(&table, key);
        if (table.count[slot] > 1) {
            status = BA_DUPLICATE;
            break;
        }
        if (table.count[slot]) {
            size_t j = (size_t)table.val[slot];
            if (used[j]) {
                status = BA_DUPLICATE;
                break;
            }
            used[j] = 1;
            ba_match *m = &out->items[out->n++];
            m->client_index = i;
            m->response_index = j;
            m->token = ba_alloc(bytes, 1);
            memcpy(m->token, key, bytes);
        }
    }
    if (optimized)
        pairing_pp_clear(pp);
    element_clear(h);
    element_clear(z);
    element_clear(token);

    free(key);

    free(used);
    ba_table_clear(&table);
    if (status != BA_OK)
        ba_matches_clear(out);
    return status;
}

void ba_matches_clear(ba_matches *m) {
    for (size_t i = 0; i < m->n; i++)
        free(m->items[i].token);

    free(m->items);
    memset(m, 0, sizeof *m);
}

static void mask(const unsigned char ctx[32],
                 const unsigned char *token,
                 size_t n,
                 unsigned char out[66]) {
    static const unsigned char info[] = "BA-APSI/EC/P-256/ciphertext-mask/v1";
    ba_require(n <= INT_MAX, "KDF input size");

    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    ba_require(c != NULL, "HKDF allocation");
    size_t size = 66;
    ba_require(EVP_PKEY_derive_init(c) > 0 && EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256()) > 0 &&
                   EVP_PKEY_CTX_set1_hkdf_salt(c, ctx, 32) > 0 &&
                   EVP_PKEY_CTX_set1_hkdf_key(c, token, (int)n) > 0 &&
                   EVP_PKEY_CTX_add1_hkdf_info(c, info, sizeof info - 1) > 0 &&
                   EVP_PKEY_derive(c, out, &size) > 0 && size == 66,
               "HKDF");
    EVP_PKEY_CTX_free(c);
}

ba_status ba_encapsulate(
    ba_public *p, ba_certificates *c, const uint64_t *values, ba_matches *m, ba_payloads *out) {
    memset(out, 0, sizeof *out);
    if (memcmp(c->period, p->period, 32) || m->n > c->n || (c->n && !values) ||
        m->token_bytes != (size_t)pairing_length_in_bytes_GT(p->pairing))
        return BA_INVALID;

    unsigned char *used = ba_alloc(c->n, 1);
    ba_table indices;
    ba_status status = ba_table_init(&indices, m->n, 8, SIZE_MAX);
    if (status != BA_OK) {
        free(used);
        return status;
    }

    for (size_t i = 0; i < m->n; i++) {
        ba_match *item = &m->items[i];
        size_t j = item->client_index;
        unsigned char key[8];
        ba_u64be(key, item->response_index);
        if (j >= c->n || item->response_index >= p->cfg.ns || !item->token ||
            values[j] > p->cfg.max_value) {
            status = BA_INVALID;
            break;
        }
        if (used[j] || indices.count[ba_table_find(&indices, key)]) {
            status = BA_DUPLICATE;
            break;
        }
        used[j] = 1;
        ba_table_insert(&indices, key, i);
    }

    free(used);
    ba_table_clear(&indices);
    if (status != BA_OK)
        return status;

    out->items = ba_alloc(m->n, sizeof(ba_packet));
    out->n = m->n;
    memcpy(out->context, m->context, 32);

    for (size_t i = 0; i < m->n; i++) {
        unsigned char k[66];
        ba_match *item = &m->items[i];
        out->items[i].index = item->response_index;
        ba_encrypt(&p->ec, p->pk, values[item->client_index], &out->items[i].masked);
        mask(m->context, item->token, m->token_bytes, k);
        for (size_t j = 0; j < 66; j++)
            out->items[i].masked.bytes[j] ^= k[j];
        OPENSSL_cleanse(k, sizeof k);
    }
    return BA_OK;
}

void ba_payloads_clear(ba_payloads *c) {
    free(c->items);
    memset(c, 0, sizeof *c);
}

ba_status ba_blind_aggregate(ba_public *p, ba_response *s, ba_payloads *c, ba_ciphertext *out) {
    if (memcmp(c->context, s->context, 32) || c->n > s->n || s->n > p->cfg.ns)
        return BA_INVALID;

    unsigned char *used = ba_alloc(s->n, 1);
    ba_status status = BA_OK;

    for (size_t i = 0; i < c->n; i++) {
        size_t j = c->items[i].index;
        if (j >= s->n) {
            status = BA_INVALID;
            break;
        }
        if (used[j]) {
            status = BA_DUPLICATE;
            break;
        }
        used[j] = 1;
    }

    free(used);
    if (status != BA_OK)
        return status;

    EC_POINT *sum1 = EC_POINT_new(p->ec.group), *sum2 = EC_POINT_new(p->ec.group),
             *x = EC_POINT_new(p->ec.group), *y = EC_POINT_new(p->ec.group);
    ba_require(sum1 && sum2 && x && y, "aggregate allocation");
    ba_require(EC_POINT_set_to_infinity(p->ec.group, sum1) == 1 &&
                   EC_POINT_set_to_infinity(p->ec.group, sum2) == 1,
               "aggregate zero");

    size_t n = (size_t)pairing_length_in_bytes_GT(p->pairing);
    unsigned char *token = ba_alloc(n, 1);

    for (size_t i = 0; i < c->n; i++) {
        unsigned char k[66], plain[66];
        ba_require(element_to_bytes(token, s->P[c->items[i].index]) == (int)n, "GT encoding");
        mask(s->context, token, n, k);
        for (size_t j = 0; j < 66; j++)
            plain[j] = c->items[i].masked.bytes[j] ^ k[j];
        status = ba_ec_decode(&p->ec, x, plain);
        if (status == BA_OK)
            status = ba_ec_decode(&p->ec, y, plain + 33);
        OPENSSL_cleanse(k, sizeof k);
        OPENSSL_cleanse(plain, sizeof plain);
        if (status != BA_OK)
            break;
        ba_require(EC_POINT_add(p->ec.group, sum1, sum1, x, p->ec.ctx) == 1 &&
                       EC_POINT_add(p->ec.group, sum2, sum2, y, p->ec.ctx) == 1,
                   "aggregate add");
    }
    if (status == BA_OK) {
        ba_ec_encode(&p->ec, sum1, out->bytes);
        ba_ec_encode(&p->ec, sum2, out->bytes + 33);
    }

    free(token);
    EC_POINT_free(sum1);
    EC_POINT_free(sum2);
    EC_POINT_free(x);
    EC_POINT_free(y);
    return status;
}

static ba_status recover_impl(ba_public *p,
                              ba_recoverer *r,
                              const ba_ciphertext *ct,
                              const ba_dlp_options *opt,
                              const ba_dlp_prepared *prepared,
                              uint64_t *answer,
                              ba_dlp_stats *stats) {
    if (!stats)
        return BA_INVALID;
    memset(stats, 0, sizeof *stats);
    if (!p || !p->active || !r || !r->sk || !ct || !answer || (!opt && !prepared))
        return BA_INVALID;
    EC_POINT *v = EC_POINT_new(p->ec.group);
    ba_require(v != NULL, "recover point");

    ba_status status = ba_decrypt_point(&p->ec, r->sk, ct, v);
    int64_t x;
    if (status == BA_OK) {
        status = prepared ? ba_dlp_execute(&p->ec, v, prepared, &x, stats)
                          : ba_dlp(&p->ec, v, 0, (int64_t)p->cfg.bound, opt, &x, stats);
    }
    if (status == BA_OK) {
        EC_POINT *check = EC_POINT_new(p->ec.group);
        ba_require(check != NULL, "recover verify allocation");
        ba_ec_mul_i64(&p->ec, check, x);
        if (x < 0 || (uint64_t)x > p->cfg.bound ||
            EC_POINT_cmp(p->ec.group, check, v, p->ec.ctx) != 0)
            status = BA_INVALID;
        else
            *answer = (uint64_t)x;
        EC_POINT_free(check);
    }

    EC_POINT_free(v);
    return status;
}

ba_status ba_recover(ba_public *p,
                     ba_recoverer *r,
                     const ba_ciphertext *ct,
                     const ba_dlp_options *opt,
                     uint64_t *answer,
                     ba_dlp_stats *stats) {
    return recover_impl(p, r, ct, opt, NULL, answer, stats);
}

ba_status ba_recover_prepared(ba_public *p,
                              ba_recoverer *r,
                              const ba_ciphertext *ct,
                              const ba_dlp_prepared *prepared,
                              uint64_t *answer,
                              ba_dlp_stats *stats) {
    if (!stats)
        return BA_INVALID;
    memset(stats, 0, sizeof *stats);
    if (!p || p->cfg.bound > INT64_MAX ||
        !ba_dlp_prepared_matches(prepared, &p->ec, 0, (int64_t)p->cfg.bound))
        return BA_INVALID;
    return recover_impl(p, r, ct, NULL, prepared, answer, stats);
}
