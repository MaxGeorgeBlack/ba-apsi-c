#include "ba.h"

#include <limits.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char seed[32];
    ba_table tame;
    uint64_t last_distance;
} prepared_walk;

struct ba_dlp_prepared {
    const ba_ec *owner;
    const EC_GROUP *group;
    int64_t a, b, anchor;
    uint64_t n, m, giant_steps, tame_steps, wild_steps;
    uint64_t max_tame_distance;
    ba_dlp_options options;
    ba_table baby;
    EC_POINT *negative_a, *negative_m, *jumps[32];
    uint64_t distances[32];
    prepared_walk *walks;
    size_t table_bytes;
    unsigned char id[32];
};

static int verify(ba_ec *e, const EC_POINT *v, int64_t x) {
    EC_POINT *p = EC_POINT_new(e->group);
    ba_require(p != NULL, "prepared DLP verification allocation");
    ba_ec_mul_i64(e, p, x);
    int ok = EC_POINT_cmp(e->group, p, v, e->ctx) == 0;
    EC_POINT_free(p);
    return ok;
}

static unsigned jump_index(const unsigned char seed[32], const unsigned char key[33]) {
    unsigned char digest[32];
    ba_digest("BA-APSI/Kangaroo/P-256/v1", seed, 32, key, 33, digest);
    return digest[0] & 31u;
}

void ba_dlp_prepared_clear(ba_dlp_prepared *p) {
    if (!p)
        return;
    ba_table_clear(&p->baby);
    if (p->walks) {
        for (unsigned i = 0; i < p->options.attempts; i++)
            ba_table_clear(&p->walks[i].tame);
    }
    free(p->walks);
    for (unsigned i = 0; i < 32; i++)
        EC_POINT_free(p->jumps[i]);
    EC_POINT_free(p->negative_a);
    EC_POINT_free(p->negative_m);
    free(p);
}

int ba_dlp_prepared_matches(const ba_dlp_prepared *p, const ba_ec *e, int64_t a, int64_t b) {
    return p && e && p->owner == e && p->group == e->group && p->a == a && p->b == b;
}

void ba_dlp_prepared_id(const ba_dlp_prepared *p, unsigned char out[32]) {
    ba_require(p && out, "prepared DLP identity");
    memcpy(out, p->id, 32);
}

static ba_status allocate_table(ba_dlp_prepared *p, ba_table *table, size_t entries) {
    size_t remaining = p->options.max_table_bytes - p->table_bytes;
    ba_status status = ba_table_init(table, entries, 33, remaining);
    if (status == BA_OK)
        p->table_bytes += table->bytes;
    return status;
}

ba_status ba_dlp_prepare(ba_ec *e,
                         int64_t a,
                         int64_t b,
                         const ba_dlp_options *opt,
                         ba_dlp_prepared **out,
                         ba_dlp_stats *s) {
    if (!out || !s)
        return BA_INVALID;
    *out = NULL;
    memset(s, 0, sizeof *s);
    if (!e || !e->group || !e->ctx || !opt || a > b ||
        (opt->solver != BA_BSGS && opt->solver != BA_KANGAROO) ||
        (opt->strategy != BA_DLP_FULL_BUDGET && opt->strategy != BA_DLP_EARLY_STOP))
        return BA_INVALID;
    __int128 width = (__int128)b - a + 1;
    if (width > INT64_MAX)
        return BA_INVALID;

    ba_dlp_prepared *p = ba_alloc(1, sizeof *p);
    p->owner = e;
    p->group = e->group;
    p->a = a;
    p->b = b;
    p->anchor = opt->strategy == BA_DLP_EARLY_STOP ? a : b;
    p->n = (uint64_t)width;
    p->m = ba_ceil_sqrt(p->n);
    p->giant_steps = (p->n + p->m - 1) / p->m;
    p->options = *opt;
    ba_status status = BA_OK;
    EC_POINT *point = NULL;
    unsigned char info[64];
    uint64_t parameters[] = {(uint64_t)a,
                             (uint64_t)b,
                             opt->solver,
                             p->m,
                             opt->tame,
                             opt->wild,
                             opt->attempts,
                             opt->strategy};
    for (size_t i = 0; i < 8; i++)
        ba_u64be(info + 8 * i, parameters[i]);
    ba_digest("BA-APSI/DLP-preprocessing/P-256/v1", info, sizeof info, NULL, 0, p->id);
    if (p->n == 1) {
        *out = p;
        return BA_OK;
    }

    if (opt->solver == BA_KANGAROO) {
        int early = opt->strategy == BA_DLP_EARLY_STOP;
        p->tame_steps = opt->tame ? opt->tame : (early ? 8 : 4) * p->m;
        p->wild_steps = opt->wild ? opt->wild : (early ? 2 : 8) * p->m;
        if (!opt->attempts || opt->attempts > 64) {
            status = BA_INVALID;
            goto finish;
        }
        if (p->tame_steps > UINT32_MAX || p->wild_steps > UINT32_MAX ||
            p->tame_steps > UINT64_MAX / (2 * p->m) || p->wild_steps > UINT64_MAX / (2 * p->m) ||
            p->tame_steps >= SIZE_MAX) {
            status = BA_RESOURCE;
            goto finish;
        }
    }

    /* Prebuild complete BSGS even for Kangaroo, so fallback only performs the
     * target-dependent giant walk. No target, ciphertext or secret key is used. */
    status = allocate_table(p, &p->baby, (size_t)p->m);
    if (status != BA_OK)
        goto finish;
    point = EC_POINT_new(e->group);
    p->negative_a = EC_POINT_new(e->group);
    p->negative_m = EC_POINT_new(e->group);
    ba_require(point && p->negative_a && p->negative_m, "prepared DLP points");
    ba_require(EC_POINT_set_to_infinity(e->group, point) == 1, "prepared baby identity");
    unsigned char key[33];
    for (uint64_t i = 0; i < p->m; i++) {
        ba_ec_encode(e, point, key);
        ba_table_insert(&p->baby, key, i);
        ba_require(
            EC_POINT_add(e->group, point, point, EC_GROUP_get0_generator(e->group), e->ctx) == 1,
            "prepared baby step");
        s->baby_steps++;
    }
    ba_ec_mul_i64(e, p->negative_a, a);
    ba_ec_mul_i64(e, p->negative_m, (int64_t)p->m);
    ba_require(EC_POINT_invert(e->group, p->negative_a, e->ctx) == 1 &&
                   EC_POINT_invert(e->group, p->negative_m, e->ctx) == 1,
               "prepared BSGS offsets");
    if (opt->solver == BA_BSGS)
        goto finish;

    /* Each public selector seed has its own immutable tame dictionary. */
    p->walks = ba_alloc(opt->attempts, sizeof *p->walks);
    for (unsigned i = 0; i < opt->attempts; i++) {
        status = allocate_table(p, &p->walks[i].tame, (size_t)p->tame_steps + 1);
        if (status != BA_OK)
            goto finish;
    }
    /* A public space/time tradeoff: smaller jumps and a longer tame path cover
     * the interval before any target exists. No target-dependent work is cached. */
    uint64_t jump_scale = opt->strategy == BA_DLP_EARLY_STOP ? (p->m + 3) / 4 : p->m;
    for (unsigned i = 0; i < 32; i++) {
        p->distances[i] = i == 0 ? 1 : 1 + ((uint64_t)(i - 1) * (2 * jump_scale - 1)) / 30;
        p->jumps[i] = EC_POINT_new(e->group);
        ba_require(p->jumps[i] != NULL, "prepared Kangaroo jump");
        ba_ec_mul_i64(e, p->jumps[i], (int64_t)p->distances[i]);
    }
    for (unsigned i = 0; i < opt->attempts; i++) {
        prepared_walk *walk = &p->walks[i];
        ba_require(RAND_bytes(walk->seed, 32) == 1, "public preprocessing seed");
        ba_digest("BA-APSI/DLP-preprocessing/P-256/v1", p->id, 32, walk->seed, 32, p->id);
        ba_ec_mul_i64(e, point, p->anchor);
        uint64_t distance = 0;
        for (uint64_t step = 0; step <= p->tame_steps; step++) {
            ba_ec_encode(e, point, key);
            ba_table_insert(&walk->tame, key, distance);
            if (step < p->tame_steps) {
                unsigned j = jump_index(walk->seed, key);
                ba_require(distance <= UINT64_MAX - p->distances[j], "prepared tame distance");
                distance += p->distances[j];
                ba_require(EC_POINT_add(e->group, point, point, p->jumps[j], e->ctx) == 1,
                           "prepared tame step");
                s->tame_steps++;
            }
        }
        walk->last_distance = distance;
        if (distance > p->max_tame_distance)
            p->max_tame_distance = distance;
        s->attempts++;
    }

finish:
    EC_POINT_free(point);
    s->peak_table_bytes = p->table_bytes;
    if (status == BA_OK)
        *out = p;
    else
        ba_dlp_prepared_clear(p);
    return status;
}

static ba_status execute_bsgs(
    ba_ec *e, const EC_POINT *v, const ba_dlp_prepared *p, int64_t *answer, ba_dlp_stats *s) {
    EC_POINT *point = EC_POINT_new(e->group);
    ba_require(point != NULL, "online BSGS point");
    ba_require(EC_POINT_add(e->group, point, v, p->negative_a, e->ctx) == 1, "online BSGS shift");
    int found = 0;
    int64_t candidate = 0;
    unsigned char key[33];
    for (uint64_t j = 0; j < p->giant_steps; j++) {
        ba_ec_encode(e, point, key);
        size_t slot = ba_table_find(&p->baby, key);
        if (p->baby.count[slot]) {
            __uint128_t distance = (__uint128_t)j * p->m + p->baby.val[slot];
            if (distance < p->n) {
                candidate = (int64_t)((__int128)p->a + (__int128)distance);
                found = 1;
                if (p->options.strategy == BA_DLP_EARLY_STOP && verify(e, v, candidate)) {
                    *answer = candidate;
                    EC_POINT_free(point);
                    return BA_OK;
                }
            }
        }
        ba_require(EC_POINT_add(e->group, point, point, p->negative_m, e->ctx) == 1,
                   "online BSGS giant step");
        s->giant_steps++;
    }
    EC_POINT_free(point);
    if (!found || !verify(e, v, candidate))
        return BA_NO_SOLUTION;
    *answer = candidate;
    return BA_OK;
}

ba_status ba_dlp_execute(
    ba_ec *e, const EC_POINT *v, const ba_dlp_prepared *p, int64_t *answer, ba_dlp_stats *s) {
    if (!s)
        return BA_INVALID;
    memset(s, 0, sizeof *s);
    if (!p || !e || p->owner != e || p->group != e->group || !v || !answer ||
        EC_POINT_is_on_curve(e->group, v, e->ctx) != 1)
        return BA_INVALID;
    s->peak_table_bytes = p->table_bytes;
    if (p->n == 1) {
        if (!verify(e, v, p->a))
            return BA_NO_SOLUTION;
        *answer = p->a;
        return BA_OK;
    }
    if (p->options.solver == BA_BSGS)
        return execute_bsgs(e, v, p, answer, s);

    EC_POINT *point = EC_POINT_new(e->group);
    ba_require(point != NULL, "online Kangaroo point");
    int found = 0;
    int64_t candidate = 0;
    unsigned char key[33];
    for (unsigned i = 0; i < p->options.attempts; i++) {
        const prepared_walk *walk = &p->walks[i];
        s->attempts++;
        ba_require(EC_POINT_copy(point, v) == 1, "online wild start");
        uint64_t distance = 0;
        int hit = 0;
        int64_t x = 0;
        for (uint64_t step = 0; step <= p->wild_steps; step++) {
            ba_ec_encode(e, point, key);
            int early = p->options.strategy == BA_DLP_EARLY_STOP;
            unsigned probes = early ? p->options.attempts : 1;
            /* Any full-point collision yields anchor + D_T - D_W, even when
             * the tame table used another public selector. Probe the whole
             * prepared herd instead of discarding its target-independent work. */
            for (unsigned probe = 0; probe < probes; probe++) {
                const ba_table *table = &p->walks[early ? probe : i].tame;
                size_t slot = ba_table_find(table, key);
                if (table->count[slot]) {
                    __int128 lifted = (__int128)p->anchor + table->val[slot] - distance;
                    if (lifted >= p->a && lifted <= p->b) {
                        x = (int64_t)lifted;
                        hit = 1;
                        if (early && verify(e, v, x)) {
                            *answer = x;
                            EC_POINT_free(point);
                            return BA_OK;
                        }
                    }
                }
            }
            /* For any x in [a,b], positive jumps cannot re-enter the tame
             * exponent range after this bound; unsuccessful walks still fall back. */
            if (p->options.strategy == BA_DLP_EARLY_STOP &&
                (__int128)p->a + distance > (__int128)p->anchor + p->max_tame_distance)
                break;
            if (step < p->wild_steps) {
                unsigned j = jump_index(walk->seed, key);
                ba_require(distance <= UINT64_MAX - p->distances[j], "online wild distance");
                distance += p->distances[j];
                ba_require(EC_POINT_add(e->group, point, point, p->jumps[j], e->ctx) == 1,
                           "online wild step");
                s->wild_steps++;
            }
        }
        if (hit && verify(e, v, x)) {
            found = 1;
            candidate = x;
        }
    }
    EC_POINT_free(point);
    if (found && verify(e, v, candidate)) {
        *answer = candidate;
        return BA_OK;
    }
    s->fallback = 1;
    return execute_bsgs(e, v, p, answer, s);
}
