#include "ba.h"

#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
static size_t checks;
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        checks++;                                                                                  \
        if (!(x)) {                                                                                \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x);                           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static int yes(uint64_t id, void *p) {
    (void)id;
    (void)p;
    return 1;
}

static int no(uint64_t id, void *p) {
    (void)id;
    (void)p;
    return 0;
}

static void test_table(void) {
    ba_table t;
    CHECK(ba_table_init(&t, 256, 8, 100000) == BA_OK);
    unsigned char key[8];
    for (uint64_t i = 0; i < 256; i++) {
        ba_u64be(key, i);
        ba_table_insert(&t, key, i + 7);
    }
    for (uint64_t i = 0; i < 256; i++) {
        ba_u64be(key, i);
        size_t slot = ba_table_find(&t, key);
        CHECK(t.count[slot] == 1 && t.val[slot] == i + 7);
    }
    ba_u64be(key, 123);
    ba_table_insert(&t, key, 999);
    size_t slot = ba_table_find(&t, key);
    CHECK(t.count[slot] == 2 && t.val[slot] == 130);
    ba_u64be(key, 999);
    CHECK(t.count[ba_table_find(&t, key)] == 0);
    ba_table_clear(&t);
    CHECK(ba_table_init(&t, SIZE_MAX, 33, 1000) == BA_RESOURCE);
    CHECK(ba_table_init(&t, 10, 33, 1) == BA_RESOURCE);
}

static void test_dlp(void) {
    ba_ec e;
    ba_ec_init(&e);
    EC_POINT *v = EC_POINT_new(e.group), *w = EC_POINT_new(e.group);
    CHECK(v && w);
    ba_dlp_options bsgs = ba_dlp_defaults(BA_BSGS), kang = ba_dlp_defaults(BA_KANGAROO);
    ba_dlp_stats st;
    int64_t answer;
    CHECK(ba_ceil_sqrt(0) == 0 && ba_ceil_sqrt(1) == 1 && ba_ceil_sqrt(2) == 2 &&
          ba_ceil_sqrt(9) == 3 && ba_ceil_sqrt(10) == 4);
    CHECK(ba_ceil_sqrt(UINT64_MAX) == UINT64_C(4294967296));
    for (int64_t a = -9; a <= 9; a += 3)
        for (int64_t n = 1; n <= 29; n += 4)
            for (int64_t x = a - 1; x <= a + n; x++) {
                ba_ec_mul_i64(&e, v, x);
                answer = 777;
                ba_status s = ba_dlp(&e, v, a, a + n - 1, &bsgs, &answer, &st);
                if (x >= a && x < a + n)
                    CHECK(s == BA_OK && answer == x);
                else
                    CHECK(s == BA_NO_SOLUTION && answer == 777);
                if (n > 1) {
                    uint64_t m = ba_ceil_sqrt((uint64_t)n);
                    CHECK(st.baby_steps == m && st.giant_steps == ((uint64_t)n + m - 1) / m);
                }
            }
    for (int64_t x = -2; x <= 18; x++) {
        ba_ec_mul_i64(&e, v, x);
        answer = 777;
        ba_status s = ba_dlp(&e, v, -1, 17, &kang, &answer, &st);
        if (x >= -1 && x <= 17)
            CHECK(s == BA_OK && answer == x);
        else
            CHECK(s == BA_NO_SOLUTION && st.fallback == 1);
        CHECK(st.attempts == 4 && st.tame_steps == 4 * 4 * 5 && st.wild_steps == 4 * 8 * 5);
    }
    ba_ec_mul_i64(&e, v, 0);
    kang.tame = 1;
    kang.wild = 1;
    kang.attempts = 1;
    CHECK(ba_dlp(&e, v, 0, 100, &kang, &answer, &st) == BA_OK && answer == 0 && st.fallback == 1 &&
          st.baby_steps == 11);
    ba_ec_mul_i64(&e, v, 101);
    CHECK(ba_dlp(&e, v, 0, 100, &kang, &answer, &st) == BA_NO_SOLUTION && st.fallback == 1);
    int64_t points[] = {0, 1, 999999, 1000000, 1000001};
    for (size_t i = 0; i < 5; i++) {
        ba_ec_mul_i64(&e, v, points[i]);
        ba_status s = ba_dlp(&e, v, 0, 1000000, &bsgs, &answer, &st);
        CHECK(points[i] <= 1000000 ? s == BA_OK && answer == points[i] : s == BA_NO_SOLUTION);
    }
    ba_ec_mul_i64(&e, v, INT64_MIN);
    CHECK(ba_dlp(&e, v, INT64_MIN, INT64_MIN + 10, &bsgs, &answer, &st) == BA_OK &&
          answer == INT64_MIN);
    ba_ec_mul_i64(&e, v, INT64_MAX);
    CHECK(ba_dlp(&e, v, INT64_MAX - 10, INT64_MAX, &bsgs, &answer, &st) == BA_OK &&
          answer == INT64_MAX);
    CHECK(ba_dlp(&e, v, 5, 4, &bsgs, &answer, &st) == BA_INVALID);
    CHECK(ba_dlp(&e, v, INT64_MIN, INT64_MAX, &bsgs, &answer, &st) == BA_INVALID);
    bsgs.max_table_bytes = 1;
    CHECK(ba_dlp(&e, v, 0, 100, &bsgs, &answer, &st) == BA_RESOURCE);
    kang.max_table_bytes = 1;
    CHECK(ba_dlp(&e, v, 0, 100, &kang, &answer, &st) == BA_RESOURCE);
    unsigned char buf[33] = {0};
    CHECK(ba_ec_decode(&e, w, buf) == BA_OK && EC_POINT_is_at_infinity(e.group, w));
    buf[32] = 1;
    CHECK(ba_ec_decode(&e, w, buf) == BA_INVALID);
    memset(buf, 255, 33);
    CHECK(ba_ec_decode(&e, w, buf) == BA_INVALID);
    memset(buf, 255, 33);
    buf[0] = 2;
    CHECK(ba_ec_decode(&e, w, buf) == BA_INVALID);
    ba_ec_mul_i64(&e, v, 7);
    ba_ec_encode(&e, v, buf);
    CHECK(ba_ec_decode(&e, w, buf) == BA_OK && EC_POINT_cmp(e.group, v, w, e.ctx) == 0);
    BIGNUM *sk = ba_bn_u64(123), *zero = ba_bn_u64(0);
    EC_POINT *pk = EC_POINT_new(e.group);
    CHECK(pk != NULL);
    ba_ec_mul_i64(&e, pk, 123);
    ba_ciphertext ct;
    ba_encrypt_with_coin(&e, pk, 0, zero, &ct);
    unsigned char empty[66] = {0};
    CHECK(!memcmp(ct.bytes, empty, 66));
    CHECK(ba_decrypt_point(&e, sk, &ct, w) == BA_OK && EC_POINT_is_at_infinity(e.group, w));
    ba_encrypt_with_coin(&e, pk, 17, zero, &ct);
    CHECK(ba_decrypt_point(&e, sk, &ct, w) == BA_OK);
    ba_ec_mul_i64(&e, v, 17);
    CHECK(EC_POINT_cmp(e.group, v, w, e.ctx) == 0);
    /* Valid encryption randomness can sum to zero modulo q. */
    BIGNUM *one = ba_bn_u64(1), *minus = BN_dup(e.order);
    CHECK(minus && BN_sub_word(minus, 1));
    ba_ciphertext c1, c2;
    ba_encrypt_with_coin(&e, pk, 3, one, &c1);
    ba_encrypt_with_coin(&e, pk, 4, minus, &c2);
    for (size_t off = 0; off < 66; off += 33) {
        CHECK(ba_ec_decode(&e, v, c1.bytes + off) == BA_OK &&
              ba_ec_decode(&e, w, c2.bytes + off) == BA_OK);
        CHECK(EC_POINT_add(e.group, v, v, w, e.ctx) == 1);
        ba_ec_encode(&e, v, ct.bytes + off);
    }
    CHECK(!memcmp(ct.bytes, empty, 33));
    CHECK(ba_decrypt_point(&e, sk, &ct, w) == BA_OK);
    ba_ec_mul_i64(&e, v, 7);
    CHECK(EC_POINT_cmp(e.group, v, w, e.ctx) == 0);
    BN_clear_free(sk);
    BN_free(zero);
    BN_free(one);
    BN_free(minus);
    EC_POINT_free(pk);
    EC_POINT_free(v);
    EC_POINT_free(w);
    ba_ec_clear(&e);
    puts("PASS full-range BSGS, Kangaroo/fallback, canonical points, zero coins and cancellation");
}

static void protocol_case(
    const char *params, size_t n, size_t m, size_t k, uint64_t max, int optimized, int allmax) {
    size_t u = n + m - k;
    ba_config cfg = {u ? u : 1, n ? n : 1, m ? m : 1, 3, max, 0};
    ba_public p;
    ba_authority a;
    ba_recoverer rec;
    CHECK(ba_setup(&p, &a, &rec, params, &cfg) == BA_OK);
    uint64_t *c = ba_alloc(n, sizeof(uint64_t)), *s = ba_alloc(m, sizeof(uint64_t)),
             *values = ba_alloc(n, sizeof(uint64_t));
    uint64_t expected = 0;
    for (size_t i = 0; i < n; i++) {
        c[i] = i + 1;
        values[i] = allmax ? max : ba_random_below(max + 1);
    }
    for (size_t i = 0; i < m; i++)
        s[i] = i < k ? i + 1 : n + i - k + 1;
    /* Independent plaintext oracle, deliberately separate from token matching. */
    size_t expected_k = 0;
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < m; j++)
            if (c[i] == s[j]) {
                expected += values[i];
                expected_k++;
            }
    ba_certificates cc, sc, repeat;
    CHECK(ba_authorize(&p, &a, c, n, yes, NULL, &cc) == BA_OK);
    CHECK(ba_authorize(&p, &a, s, m, yes, NULL, &sc) == BA_OK);
    CHECK(ba_authorize(&p, &a, c, n, yes, NULL, &repeat) == BA_OK);
    for (size_t i = 0; i < n; i++)
        CHECK(element_cmp(cc.sigma[i], repeat.sigma[i]) == 0);
    ba_certificates_clear(&repeat);
    /* Independent algebraic check of the optimized server transformation. */
    element_t y, rs, left, right;
    element_init_Zr(y, p.pairing);
    element_init_G1(rs, p.pairing);
    element_init_GT(left, p.pairing);
    element_init_GT(right, p.pairing);
    element_set_si(y, 37);
    element_pow_zn(rs, p.g, y);
    pairing_pp_t pp;
    pairing_pp_init(pp, rs, p.pairing);
    for (size_t i = 0; i < sc.n; i++) {
        pairing_apply(left, p.g, sc.sigma[i], p.pairing);
        element_pow_zn(left, left, y);
        pairing_pp_apply(right, sc.sigma[i], pp);
        CHECK(element_cmp(left, right) == 0);
    }
    pairing_pp_clear(pp);
    element_clear(y);
    element_clear(rs);
    element_clear(left);
    element_clear(right);
    unsigned char session[32] = {0}, ctx[32];
    ba_context(&p, "client", "server", session, ctx);
    ba_request req;
    ba_response response;
    ba_matches matches, other;
    ba_payloads payload;
    ba_ciphertext agg;
    ba_dlp_stats st;
    uint64_t answer;
    ba_client_begin(&p, ctx, &req);
    CHECK(ba_server_respond(&p, &sc, &req, ctx, optimized, &response) == BA_OK);
    CHECK(ba_client_match(&p, &cc, &req, &response, optimized, &matches) == BA_OK &&
          matches.n == expected_k);
    CHECK(ba_client_match(&p, &cc, &req, &response, !optimized, &other) == BA_OK &&
          other.n == matches.n);
    for (size_t i = 0; i < matches.n; i++) {
        CHECK(matches.items[i].client_index == other.items[i].client_index &&
              matches.items[i].response_index == other.items[i].response_index);
        CHECK(!memcmp(matches.items[i].token, other.items[i].token, matches.token_bytes));
        CHECK(c[matches.items[i].client_index] ==
              s[response.source[matches.items[i].response_index]]);
    }
    ba_matches_clear(&other);
    CHECK(ba_encapsulate(&p, &cc, values, &matches, &payload) == BA_OK);
    CHECK(ba_blind_aggregate(&p, &response, &payload, &agg) == BA_OK);
    for (unsigned solver = 0; solver < 2; solver++) {
        ba_dlp_options opt = ba_dlp_defaults((ba_solver)solver);
        CHECK(ba_recover(&p, &rec, &agg, &opt, &answer, &st) == BA_OK && answer == expected);
    }
    if (k == 0) {
        unsigned char zero[66] = {0};
        CHECK(!memcmp(agg.bytes, zero, 66));
    }
    ba_payloads_clear(&payload);
    ba_matches_clear(&matches);
    ba_response_clear(&response);
    ba_request_clear(&req);
    ba_certificates_clear(&cc);
    ba_certificates_clear(&sc);
    ba_setup_clear(&p, &a, &rec);
    free(c);
    free(s);
    free(values);
}

static void test_rejections(const char *params) {
    ba_config cfg = {8, 3, 3, 2, 10, 0};
    ba_public p;
    ba_authority a;
    ba_recoverer rec;
    CHECK(ba_setup(&p, &a, &rec, params, &cfg) == BA_OK);
    ba_certificates cc, sc, bad;
    uint64_t c[] = {1, 2, 3}, s[] = {1, 2, 4}, duplicate[] = {1, 1}, out[] = {0, 9},
             values[] = {5, 6, 7};
    CHECK(ba_authorize(&p, &a, duplicate, 2, yes, NULL, &bad) == BA_DUPLICATE);
    CHECK(ba_authorize(&p, &a, out, 2, yes, NULL, &bad) == BA_INVALID);
    CHECK(ba_authorize(&p, &a, c, 3, no, NULL, &bad) == BA_INVALID);
    CHECK(ba_authorize(&p, &a, c, 3, NULL, NULL, &bad) == BA_INVALID);
    CHECK(ba_authorize(&p, &a, c, 3, yes, NULL, &cc) == BA_OK);
    CHECK(ba_authorize(&p, &a, s, 3, yes, NULL, &sc) == BA_OK);
    unsigned char session[32] = {0}, ctx[32], wrong[32];
    ba_context(&p, "client", "server", session, ctx);
    session[0] = 1;
    ba_context(&p, "client", "server", session, wrong);
    CHECK(memcmp(ctx, wrong, 32));
    ba_request req;
    ba_client_begin(&p, ctx, &req);
    ba_response rsp;
    ba_matches match;
    ba_payloads payload;
    ba_ciphertext agg;
    ba_dlp_stats st;
    uint64_t answer;
    CHECK(ba_server_respond(&p, &sc, &req, wrong, 1, &rsp) == BA_INVALID);
    sc.period[0] ^= 1;
    CHECK(ba_server_respond(&p, &sc, &req, ctx, 1, &rsp) == BA_INVALID);
    sc.period[0] ^= 1;
    element_t saved;
    element_init_G1(saved, p.pairing);
    element_set(saved, req.rc);
    element_set1(req.rc);
    CHECK(ba_server_respond(&p, &sc, &req, ctx, 1, &rsp) == BA_INVALID);
    element_set(req.rc, saved);
    CHECK(ba_server_respond(&p, &sc, &req, ctx, 1, &rsp) == BA_OK);
    rsp.context[0] ^= 1;
    CHECK(ba_client_match(&p, &cc, &req, &rsp, 1, &match) == BA_INVALID);
    rsp.context[0] ^= 1;
    element_set(saved, rsp.rs);
    element_set1(rsp.rs);
    CHECK(ba_client_match(&p, &cc, &req, &rsp, 1, &match) == BA_INVALID);
    element_set(rsp.rs, saved);
    CHECK(ba_client_match(&p, &cc, &req, &rsp, 1, &match) == BA_OK && match.n == 2);
    values[0] = 11;
    CHECK(ba_encapsulate(&p, &cc, values, &match, &payload) == BA_INVALID);
    values[0] = 5;
    CHECK(ba_encapsulate(&p, &cc, values, &match, &payload) == BA_OK);
    size_t keep = payload.items[1].index;
    payload.items[1].index = payload.items[0].index;
    CHECK(ba_blind_aggregate(&p, &rsp, &payload, &agg) == BA_DUPLICATE);
    payload.items[1].index = keep;
    payload.items[0].index = 3;
    CHECK(ba_blind_aggregate(&p, &rsp, &payload, &agg) == BA_INVALID);
    payload.items[0].index = match.items[0].response_index;
    payload.context[0] ^= 1;
    CHECK(ba_blind_aggregate(&p, &rsp, &payload, &agg) == BA_INVALID);
    payload.context[0] ^= 1;
    payload.items[0].masked.bytes[0] ^= 255;
    CHECK(ba_blind_aggregate(&p, &rsp, &payload, &agg) == BA_INVALID);
    payload.items[0].masked.bytes[0] ^= 255;
    CHECK(ba_blind_aggregate(&p, &rsp, &payload, &agg) == BA_OK);
    ba_dlp_options opt = ba_dlp_defaults(BA_BSGS);
    CHECK(ba_recover(&p, &rec, &agg, &opt, &answer, &st) == BA_OK && answer == 11);
    agg.bytes[0] = 255;
    CHECK(ba_recover(&p, &rec, &agg, &opt, &answer, &st) == BA_INVALID);
    ba_encrypt(&p.ec, p.pk, 31, &agg);
    CHECK(ba_recover(&p, &rec, &agg, &opt, &answer, &st) == BA_NO_SOLUTION);
    ba_payloads_clear(&payload);
    ba_matches_clear(&match);
    /* Duplicate GT responses must not be overwritten in the dictionary. */
    size_t p0 = 0, p1 = 0;
    for (size_t i = 0; i < rsp.n; i++) {
        if (rsp.source[i] == 0)
            p0 = i;
        if (rsp.source[i] == 1)
            p1 = i;
    }
    element_t gt;
    element_init_GT(gt, p.pairing);
    element_set(gt, rsp.P[p1]);
    element_set(rsp.P[p1], rsp.P[p0]);
    CHECK(ba_client_match(&p, &cc, &req, &rsp, 1, &match) == BA_DUPLICATE);
    element_set(rsp.P[p1], gt);
    element_clear(gt);
    element_set(saved, cc.sigma[1]);
    element_set(cc.sigma[1], cc.sigma[0]);
    CHECK(ba_client_match(&p, &cc, &req, &rsp, 1, &match) == BA_DUPLICATE);
    element_set(cc.sigma[1], saved);
    cc.ids[1] = cc.ids[0];
    CHECK(ba_client_match(&p, &cc, &req, &rsp, 1, &match) == BA_DUPLICATE);
    cc.ids[1] = 2;
    p.cfg.nc = 2;
    CHECK(ba_client_match(&p, &cc, &req, &rsp, 1, &match) == BA_INVALID);
    p.cfg.nc = 3;
    element_clear(saved);
    ba_response_clear(&rsp);
    ba_request_clear(&req);
    ba_certificates_clear(&cc);
    ba_certificates_clear(&sc);
    /* q(1)=0 is permitted by the paper; identity certificates must work. */
    element_neg(a.coeff[1], a.coeff[0]);
    uint64_t one[] = {1}, zero[] = {0};
    CHECK(ba_authorize(&p, &a, one, 1, yes, NULL, &cc) == BA_OK && element_is1(cc.sigma[0]));
    CHECK(ba_authorize(&p, &a, one, 1, yes, NULL, &sc) == BA_OK);
    ba_client_begin(&p, ctx, &req);
    CHECK(ba_server_respond(&p, &sc, &req, ctx, 1, &rsp) == BA_OK);
    CHECK(ba_client_match(&p, &cc, &req, &rsp, 1, &match) == BA_OK && match.n == 1);
    CHECK(ba_encapsulate(&p, &cc, zero, &match, &payload) == BA_OK);
    CHECK(ba_blind_aggregate(&p, &rsp, &payload, &agg) == BA_OK);
    CHECK(ba_recover(&p, &rec, &agg, &opt, &answer, &st) == BA_OK && answer == 0);
    ba_payloads_clear(&payload);
    ba_matches_clear(&match);
    ba_response_clear(&rsp);
    ba_request_clear(&req);
    ba_certificates_clear(&cc);
    ba_certificates_clear(&sc);
    ba_setup_clear(&p, &a, &rec);
    cfg.max_value = UINT64_MAX;
    CHECK(ba_setup(&p, &a, &rec, params, &cfg) == BA_INVALID);
    cfg.max_value = INT64_MAX / 2;
    CHECK(ba_setup(&p, &a, &rec, params, &cfg) == BA_INVALID);
    puts(
        "PASS authorization refusal, duplicates, context/period mismatch, malformed ciphertext, capacity and overflow");
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    ba_random_init();
    test_table();
    test_dlp();
    protocol_case(argv[1], 0, 0, 0, 0, 1, 0);
    protocol_case(argv[1], 0, 3, 0, 10, 1, 0);
    protocol_case(argv[1], 3, 0, 0, 10, 0, 0);
    protocol_case(argv[1], 3, 3, 0, 10, 1, 0);
    protocol_case(argv[1], 3, 3, 3, 10, 0, 1);
    protocol_case(argv[1], 3, 3, 3, 0, 1, 1);
    for (size_t i = 0; i < 16; i++) {
        size_t n = (size_t)ba_random_below(10), m = (size_t)ba_random_below(10),
               k = (size_t)ba_random_below((n < m ? n : m) + 1);
        protocol_case(argv[1], n, m, k, 17, (int)(i % 2), 0);
    }
    test_rejections(argv[1]);
    printf(
        "PASS %zu checks; exact set/sum oracle and reference/optimized client differential tests\n",
        checks);
    return 0;
}
