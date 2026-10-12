#include "ba.h"

#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        checks++;                                                                                  \
        if (!(x)) {                                                                                \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x);                           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void interval_case(
    ba_ec *e, int64_t a, uint64_t n, ba_solver solver, ba_dlp_strategy strategy) {
    ba_dlp_options options = ba_dlp_defaults(solver);
    options.strategy = strategy;
    ba_dlp_options reference_options = options;
    reference_options.strategy = BA_DLP_FULL_BUDGET;
    ba_dlp_prepared *prepared = NULL;
    ba_dlp_stats offline, online, cold;
    int64_t b = (int64_t)((__int128)a + n - 1);
    CHECK(ba_dlp_prepare(e, a, b, &options, &prepared, &offline) == BA_OK);
    CHECK(ba_dlp_prepared_matches(prepared, e, a, b));
    unsigned char id[32], after[32];
    ba_dlp_prepared_id(prepared, id);
    EC_POINT *point = EC_POINT_new(e->group);
    CHECK(point != NULL);
    uint64_t m = ba_ceil_sqrt(n);
    CHECK(offline.baby_steps == (n > 1 ? m : 0));
    CHECK(offline.giant_steps == 0 && offline.wild_steps == 0);
    CHECK(offline.peak_table_bytes <= options.max_table_bytes);
    for (int pass = 0; pass < 2; pass++) {
        for (uint64_t offset = 0; offset < n + 2; offset++) {
            __int128 value = (__int128)a + offset - 1;
            if (value < INT64_MIN || value > INT64_MAX)
                continue;
            int64_t x = (int64_t)value, answer = 777, reference = 777;
            ba_ec_mul_i64(e, point, x);
            ba_status status = ba_dlp_execute(e, point, prepared, &answer, &online);
            ba_status expected = ba_dlp(e, point, a, b, &reference_options, &reference, &cold);
            CHECK(status == expected && answer == reference);
            CHECK(status == (x >= a && x <= b ? BA_OK : BA_NO_SOLUTION));
            CHECK(online.baby_steps == 0 && online.tame_steps == 0);
            CHECK(online.peak_table_bytes == offline.peak_table_bytes);
            if (n > 1 && solver == BA_KANGAROO) {
                CHECK(offline.tame_steps == (strategy == BA_DLP_EARLY_STOP ? 32 : 16) * m &&
                      offline.attempts == 4);
                CHECK(online.attempts >= 1 && online.attempts <= 4);
                if (strategy == BA_DLP_FULL_BUDGET)
                    CHECK(online.wild_steps == 32 * m && online.attempts == 4);
                else
                    CHECK(online.wild_steps <= online.attempts * 2 * m);
            }
            if (n > 1 && (solver == BA_BSGS || online.fallback)) {
                if (strategy == BA_DLP_EARLY_STOP && status == BA_OK)
                    CHECK(online.giant_steps == (uint64_t)((__int128)x - a) / m);
                else
                    CHECK(online.giant_steps == (n + m - 1) / m);
            }
            /* x=a is itself in the prepared tame table; no online walk is needed. */
            if (strategy == BA_DLP_EARLY_STOP && solver == BA_KANGAROO && x == a && n > 1)
                CHECK(online.wild_steps == 0 && online.attempts == 1 && !online.fallback);
            ba_dlp_prepared_id(prepared, after);
            CHECK(!memcmp(id, after, sizeof id));
        }
    }
    ba_ec other;
    ba_ec_init(&other);
    int64_t sentinel = 777;
    CHECK(!ba_dlp_prepared_matches(prepared, &other, a, b));
    CHECK(ba_dlp_execute(&other, point, prepared, &sentinel, &online) == BA_INVALID &&
          sentinel == 777);
    CHECK(ba_dlp_execute(e, NULL, prepared, &sentinel, &online) == BA_INVALID);
    CHECK(ba_dlp_execute(e, point, NULL, &sentinel, &online) == BA_INVALID);
    ba_ec_clear(&other);
    EC_POINT_free(point);
    ba_dlp_prepared_clear(prepared);
}

static void fallback_and_resource(ba_ec *e) {
    ba_dlp_options options = ba_dlp_defaults(BA_KANGAROO);
    options.tame = options.wild = options.attempts = 1;
    ba_dlp_prepared *prepared = NULL;
    ba_dlp_stats offline, online;
    CHECK(ba_dlp_prepare(e, 0, 100, &options, &prepared, &offline) == BA_OK);
    EC_POINT *point = EC_POINT_new(e->group);
    int64_t answer = 777;
    ba_ec_mul_i64(e, point, 0);
    CHECK(ba_dlp_execute(e, point, prepared, &answer, &online) == BA_OK && answer == 0);
    CHECK(online.fallback == 1 && online.baby_steps == 0 && online.giant_steps == 10);
    ba_ec_mul_i64(e, point, 101);
    answer = 777;
    CHECK(ba_dlp_execute(e, point, prepared, &answer, &online) == BA_NO_SOLUTION && answer == 777);
    CHECK(online.fallback == 1);
    ba_dlp_prepared_clear(prepared);
    EC_POINT_free(point);

    CHECK(ba_dlp_prepare(e, 5, 4, &options, &prepared, &offline) == BA_INVALID && !prepared);
    CHECK(ba_dlp_prepare(e, INT64_MIN, INT64_MAX, &options, &prepared, &offline) == BA_INVALID);
    options.attempts = 0;
    CHECK(ba_dlp_prepare(e, 0, 100, &options, &prepared, &offline) == BA_INVALID && !prepared);
    options.attempts = 65;
    CHECK(ba_dlp_prepare(e, 0, 100, &options, &prepared, &offline) == BA_INVALID && !prepared);
    options = ba_dlp_defaults(BA_KANGAROO);
    options.tame = UINT64_MAX;
    CHECK(ba_dlp_prepare(e, 0, 100, &options, &prepared, &offline) == BA_RESOURCE && !prepared);
    options = ba_dlp_defaults(BA_BSGS);
    options.max_table_bytes = 1;
    CHECK(ba_dlp_prepare(e, 0, 100, &options, &prepared, &offline) == BA_RESOURCE && !prepared);
    /* A budget that fits one tame table must still reject four retained tables. */
    options = ba_dlp_defaults(BA_KANGAROO);
    options.max_table_bytes = 10000;
    CHECK(ba_dlp_prepare(e, 0, 100, &options, &prepared, &offline) == BA_RESOURCE && !prepared);
    options = ba_dlp_defaults(BA_KANGAROO);
    options.strategy = BA_DLP_EARLY_STOP;
    options.tame = options.wild = options.attempts = 1;
    CHECK(ba_dlp_prepare(e, 0, 100, &options, &prepared, &offline) == BA_OK);
    point = EC_POINT_new(e->group);
    ba_ec_mul_i64(e, point, 100);
    CHECK(ba_dlp_execute(e, point, prepared, &answer, &online) == BA_OK && answer == 100);
    CHECK(online.fallback == 1 && online.giant_steps == 9 && online.attempts == 1);
    ba_ec_mul_i64(e, point, 101);
    answer = 777;
    CHECK(ba_dlp_execute(e, point, prepared, &answer, &online) == BA_NO_SOLUTION && answer == 777);
    CHECK(online.fallback == 1 && online.giant_steps == 10);
    EC_POINT_free(point);
    ba_dlp_prepared_clear(prepared);
    options.strategy = (ba_dlp_strategy)2;
    CHECK(ba_dlp_prepare(e, 0, 100, &options, &prepared, &offline) == BA_INVALID && !prepared);
    ba_dlp_prepared_clear(NULL);
}

static void protocol_case(const char *params) {
    ba_public p;
    ba_authority authority;
    ba_recoverer recoverer;
    ba_config cfg = {8, 4, 4, 3, 10, 40};
    CHECK(ba_setup(&p, &authority, &recoverer, params, &cfg) == BA_OK);
    ba_dlp_stats offline, online;
    ba_ciphertext ciphertext;
    for (int variant = 0; variant < 4; variant++) {
        int solver = variant % 2;
        ba_dlp_options options = ba_dlp_defaults((ba_solver)solver);
        options.strategy = variant / 2 ? BA_DLP_EARLY_STOP : BA_DLP_FULL_BUDGET;
        ba_dlp_prepared *prepared = NULL;
        CHECK(ba_dlp_prepare(&p.ec, 0, 40, &options, &prepared, &offline) == BA_OK);
        for (uint64_t x = 0; x <= 41; x++) {
            ba_encrypt(&p.ec, p.pk, x, &ciphertext);
            uint64_t answer = UINT64_MAX;
            ba_status status =
                ba_recover_prepared(&p, &recoverer, &ciphertext, prepared, &answer, &online);
            CHECK(x <= 40 ? status == BA_OK && answer == x
                          : status == BA_NO_SOLUTION && answer == UINT64_MAX);
        }
        ciphertext.bytes[0] = 255;
        uint64_t answer = UINT64_MAX;
        CHECK(ba_recover_prepared(&p, &recoverer, &ciphertext, prepared, &answer, &online) ==
              BA_INVALID);
        p.cfg.bound = 39;
        ba_encrypt(&p.ec, p.pk, 0, &ciphertext);
        CHECK(ba_recover_prepared(&p, &recoverer, &ciphertext, prepared, &answer, &online) ==
              BA_INVALID);
        p.cfg.bound = 40;
        ba_dlp_prepared_clear(prepared);
    }
    ba_setup_clear(&p, &authority, &recoverer);
}

static void large_interval(ba_ec *e) {
    const int64_t bound = 10000000;
    for (int solver = BA_BSGS; solver <= BA_KANGAROO; solver++) {
        ba_dlp_options options = ba_dlp_defaults((ba_solver)solver);
        options.strategy = BA_DLP_EARLY_STOP;
        ba_dlp_prepared *prepared = NULL;
        ba_dlp_stats offline, online, reference_stats;
        CHECK(ba_dlp_prepare(e, 0, bound, &options, &prepared, &offline) == BA_OK);
        ba_dlp_options reference_options = ba_dlp_defaults(BA_BSGS);
        EC_POINT *point = EC_POINT_new(e->group);
        for (unsigned run = 0; run < 27; run++) {
            /* Public endpoints and uniformly spaced targets, independent of tame seeds. */
            int64_t target = run < 26 ? (int64_t)((uint64_t)run * (uint64_t)bound / 25) : bound + 1;
            int64_t answer = -1, reference = -1;
            ba_ec_mul_i64(e, point, target);
            ba_status status = ba_dlp_execute(e, point, prepared, &answer, &online);
            ba_status expected =
                ba_dlp(e, point, 0, bound, &reference_options, &reference, &reference_stats);
            CHECK(status == expected && answer == reference);
            CHECK(status == (target <= bound ? BA_OK : BA_NO_SOLUTION));
            CHECK(online.baby_steps == 0 && online.tame_steps == 0);
        }
        EC_POINT_free(point);
        ba_dlp_prepared_clear(prepared);
    }
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    ba_random_init();
    ba_ec e;
    ba_ec_init(&e);
    for (int variant = 0; variant < 4; variant++) {
        int solver = variant % 2;
        ba_dlp_strategy strategy = variant / 2 ? BA_DLP_EARLY_STOP : BA_DLP_FULL_BUDGET;
        for (int64_t a = -9; a <= 9; a += 3)
            for (uint64_t n = 1; n <= 29; n += 4)
                interval_case(&e, a, n, (ba_solver)solver, strategy);
        interval_case(&e, INT64_MIN, 11, (ba_solver)solver, strategy);
        interval_case(&e, INT64_MAX - 10, 11, (ba_solver)solver, strategy);
    }
    fallback_and_resource(&e);
    large_interval(&e);
    ba_ec_clear(&e);
    protocol_case(argv[1]);
    printf(
        "PASS %zu prepared-DLP checks: cold differential, repeated targets, bounds, fallback, resource cleanup and real ciphertexts\n",
        checks);
    return 0;
}
