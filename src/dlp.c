#include "ba.h"

#include <openssl/rand.h>
#include <string.h>
#include <limits.h>

/* Fixed P-256 suite. Public intervals fit signed 64-bit, width <= INT64_MAX.
 * Kangaroo budgets <= 2^32-1 and jumps <= 2^33: distances fit uint64/128.
 * Their absolute exponent differences are far below q, so the paper's
 * mod-q interval lift is equivalent to the signed in-range check below. */
uint64_t ba_ceil_sqrt(uint64_t n) {
    if (n <= 1)
        return n;

    uint64_t lo = 1, hi = UINT64_C(1) << 32;
    while (lo < hi) {
        uint64_t m = lo + (hi - lo) / 2;
        if ((__uint128_t)m * m >= n)
            hi = m;
        else
            lo = m + 1;
    }
    return lo;
}

ba_dlp_options ba_dlp_defaults(ba_solver solver) {
    ba_dlp_options o = {solver, 256u * 1024u * 1024u, 0, 0, 4, BA_DLP_FULL_BUDGET};
    return o;
}

static int verify(ba_ec *e, const EC_POINT *v, int64_t x) {
    EC_POINT *p = EC_POINT_new(e->group);
    ba_require(p != NULL, "DLP verification allocation");

    ba_ec_mul_i64(e, p, x);
    int ok = EC_POINT_cmp(e->group, p, v, e->ctx) == 0;

    EC_POINT_free(p);
    return ok;
}

static ba_status bsgs(ba_ec *e,
                      const EC_POINT *v,
                      int64_t a,
                      uint64_t n,
                      const ba_dlp_options *o,
                      int64_t *answer,
                      ba_dlp_stats *s) {
    uint64_t m = ba_ceil_sqrt(n), steps = (n + m - 1) / m;

    ba_table table;
    ba_status status = ba_table_init(&table, (size_t)m, 33, o->max_table_bytes);
    if (status != BA_OK)
        return status;
    if (table.bytes > s->peak_table_bytes)
        s->peak_table_bytes = table.bytes;

    EC_POINT *p = EC_POINT_new(e->group), *y = EC_POINT_new(e->group), *q = EC_POINT_new(e->group);
    ba_require(p && y && q, "BSGS points");
    ba_require(EC_POINT_set_to_infinity(e->group, p) == 1, "BSGS identity");

    unsigned char key[33];
    for (uint64_t i = 0; i < m; i++) {
        ba_ec_encode(e, p, key);
        ba_table_insert(&table, key, i);
        ba_require(EC_POINT_add(e->group, p, p, EC_GROUP_get0_generator(e->group), e->ctx) == 1,
                   "BSGS baby step");
        s->baby_steps++;
    }

    ba_ec_mul_i64(e, q, (int64_t)m);
    ba_require(EC_POINT_invert(e->group, q, e->ctx) == 1, "BSGS inverse Q");
    ba_ec_mul_i64(e, y, a);
    ba_require(EC_POINT_invert(e->group, y, e->ctx) == 1, "BSGS inverse aG");
    ba_require(EC_POINT_add(e->group, y, v, y, e->ctx) == 1, "BSGS shift");

    int found = 0;
    int64_t candidate = 0;

    /* Run the full public budget, even when a candidate is found. */
    for (uint64_t j = 0; j < steps; j++) {
        ba_ec_encode(e, y, key);
        size_t slot = ba_table_find(&table, key);
        if (table.count[slot]) {
            __uint128_t d = (__uint128_t)j * m + table.val[slot];
            if (d < n) {
                candidate = (int64_t)((__int128)a + (__int128)d);
                found = 1;
            }
        }
        ba_require(EC_POINT_add(e->group, y, y, q, e->ctx) == 1, "BSGS giant step");
        s->giant_steps++;
    }

    status = BA_NO_SOLUTION;

    if (found && verify(e, v, candidate)) {
        *answer = candidate;
        status = BA_OK;
    }

    EC_POINT_free(p);
    EC_POINT_free(y);
    EC_POINT_free(q);
    ba_table_clear(&table);
    return status;
}

static unsigned jump_index(const unsigned char seed[32], const unsigned char key[33]) {
    unsigned char h[32];
    ba_digest("BA-APSI/Kangaroo/P-256/v1", seed, 32, key, 33, h);
    return h[0] & 31u;
}

static ba_status kangaroo(ba_ec *e,
                          const EC_POINT *v,
                          int64_t a,
                          int64_t b,
                          uint64_t n,
                          const ba_dlp_options *o,
                          int64_t *answer,
                          ba_dlp_stats *s) {
    uint64_t m = ba_ceil_sqrt(n), t = o->tame ? o->tame : 4 * m, w = o->wild ? o->wild : 8 * m;
    if (!o->attempts || o->attempts > 64)
        return BA_INVALID;
    if (t > UINT32_MAX || w > UINT32_MAX || t > UINT64_MAX / (2 * m) || w > UINT64_MAX / (2 * m))
        return BA_RESOURCE;

    ba_table table;
    ba_status status = ba_table_init(&table, (size_t)t + 1, 33, o->max_table_bytes);
    if (status != BA_OK)
        return status;
    if (table.bytes > s->peak_table_bytes)
        s->peak_table_bytes = table.bytes;

    EC_POINT *jumps[32], *p = EC_POINT_new(e->group);
    uint64_t d[32];
    ba_require(p != NULL, "Kangaroo point");
    for (unsigned i = 0; i < 32; i++) {
        d[i] = i == 0 ? 1 : 1 + ((uint64_t)(i - 1) * (2 * m - 1)) / 30;
        jumps[i] = EC_POINT_new(e->group);
        ba_require(jumps[i] != NULL, "Kangaroo jump");
        ba_ec_mul_i64(e, jumps[i], (int64_t)d[i]);
    }

    int found = 0;
    int64_t candidate = 0;
    for (unsigned attempt = 0; attempt < o->attempts; attempt++) {
        unsigned char seed[32], key[33];
        ba_require(RAND_bytes(seed, 32) == 1, "Kangaroo seed");
        memset(table.count, 0, table.cap * sizeof *table.count);
        table.len = 0;
        uint64_t dt = 0, dw = 0;
        ba_ec_mul_i64(e, p, b);
        for (uint64_t k = 0; k <= t; k++) {
            ba_ec_encode(e, p, key);
            ba_table_insert(&table, key, dt);
            if (k < t) {
                unsigned j = jump_index(seed, key);
                ba_require(dt <= UINT64_MAX - d[j], "tame distance overflow");
                dt += d[j];
                ba_require(EC_POINT_add(e->group, p, p, jumps[j], e->ctx) == 1, "tame step");
                s->tame_steps++;
            }
        }

        ba_require(EC_POINT_copy(p, v) == 1, "wild start");
        int hit = 0;
        int64_t x = 0;
        for (uint64_t k = 0; k <= w; k++) {
            ba_ec_encode(e, p, key);
            size_t slot = ba_table_find(&table, key);
            if (table.count[slot]) {
                __int128 lifted = (__int128)b + table.val[slot] - dw;
                if (lifted >= a && lifted <= b) {
                    x = (int64_t)lifted;
                    hit = 1;
                }
            }
            if (k < w) {
                unsigned j = jump_index(seed, key);
                ba_require(dw <= UINT64_MAX - d[j], "wild distance overflow");
                dw += d[j];
                ba_require(EC_POINT_add(e->group, p, p, jumps[j], e->ctx) == 1, "wild step");
                s->wild_steps++;
            }
        }

        if (hit && verify(e, v, x)) {
            found = 1;
            candidate = x;
        }
        s->attempts++;
    }

    for (unsigned i = 0; i < 32; i++)
        EC_POINT_free(jumps[i]);

    EC_POINT_free(p);
    ba_table_clear(&table);

    if (found && verify(e, v, candidate)) {
        *answer = candidate;
        return BA_OK;
    }

    s->fallback = 1;
    return bsgs(e, v, a, n, o, answer, s);
}

ba_status ba_dlp(ba_ec *e,
                 const EC_POINT *v,
                 int64_t a,
                 int64_t b,
                 const ba_dlp_options *o,
                 int64_t *answer,
                 ba_dlp_stats *s) {
    memset(s, 0, sizeof *s);
    if (a > b || !o || o->strategy != BA_DLP_FULL_BUDGET || !answer ||
        EC_POINT_is_on_curve(e->group, v, e->ctx) != 1)
        return BA_INVALID;

    __int128 width = (__int128)b - a + 1;
    if (width > INT64_MAX)
        return BA_INVALID;
    uint64_t n = (uint64_t)width;
    if (o->solver != BA_BSGS && o->solver != BA_KANGAROO)
        return BA_INVALID;

    if (n == 1) {
        if (verify(e, v, a)) {
            *answer = a;
            return BA_OK;
        }
        return BA_NO_SOLUTION;
    }
    return o->solver == BA_BSGS ? bsgs(e, v, a, n, o, answer, s)
                                : kangaroo(e, v, a, b, n, o, answer, s);
}
