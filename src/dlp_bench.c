#include "experiment_util.h"

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr, "Usage: ba_dlp_bench BOUND SUM SOLVER REPEATS WARMUP CSV\n");
        return 2;
    }
    uint64_t bound = ex_parse(argv[1]), sum = ex_parse(argv[2]), reps = ex_parse(argv[4]),
             warm = ex_parse(argv[5]);
    ba_require(bound < INT64_MAX && sum <= bound && reps && reps <= 10000 && warm <= 1000,
               "DLP limits");
    ba_dlp_options opt = ba_dlp_defaults(BA_BSGS);
    if (!strcmp(argv[3], "kangaroo"))
        opt.solver = BA_KANGAROO;
    else
        ba_require(!strcmp(argv[3], "bsgs"), "solver");
    FILE *f = fopen(argv[6], "wx");
    ba_require(f != NULL, "new DLP CSV");
    ba_ec ec;
    ba_ec_init(&ec);
    BIGNUM *sk = BN_new();
    EC_POINT *pk = EC_POINT_new(ec.group), *v = EC_POINT_new(ec.group);
    ba_require(sk && pk && v, "DLP benchmark allocation");
    do {
        ba_require(BN_priv_rand_range(sk, ec.order) == 1, "sk");
    } while (BN_is_zero(sk));
    ba_require(EC_POINT_mul(ec.group, pk, sk, NULL, NULL, ec.ctx) == 1, "pk");
    fputs(
        "bound,sum,solver,rep,recover_ms,baby_steps,giant_steps,tame_steps,wild_steps,attempts,fallback,table_bytes,validation\n",
        f);
    for (uint64_t i = 0; i < reps + warm; i++) {
        ba_ciphertext ct;
        ba_encrypt(&ec, pk, sum, &ct);
        ba_dlp_stats st;
        int64_t recovered = -1;
        double start = ba_now_ms();
        ex_check(ba_decrypt_point(&ec, sk, &ct, v), "decrypt");
        ex_check(ba_dlp(&ec, v, 0, (int64_t)bound, &opt, &recovered, &st), "DLP");
        EC_POINT *check = EC_POINT_new(ec.group);
        ba_require(check != NULL, "verify");
        ba_ec_mul_i64(&ec, check, recovered);
        ba_require(EC_POINT_cmp(ec.group, v, check, ec.ctx) == 0, "verify result");
        EC_POINT_free(check);
        double ms = ba_now_ms() - start;
        ba_require(recovered == (int64_t)sum, "sum oracle");
        if (i >= warm)
            fprintf(f,
                    "%" PRIu64 ",%" PRIu64 ",%s,%" PRIu64 ",%.6f,%" PRIu64 ",%" PRIu64 ",%" PRIu64
                    ",%" PRIu64 ",%u,%d,%zu,PASS\n",
                    bound,
                    sum,
                    argv[3],
                    i - warm,
                    ms,
                    st.baby_steps,
                    st.giant_steps,
                    st.tame_steps,
                    st.wild_steps,
                    st.attempts,
                    st.fallback,
                    st.peak_table_bytes);
    }
    EC_POINT_free(v);
    EC_POINT_free(pk);
    BN_clear_free(sk);
    ba_ec_clear(&ec);
    ba_require(fclose(f) == 0, "CSV close");
    return 0;
}
