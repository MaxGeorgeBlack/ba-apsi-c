#define _POSIX_C_SOURCE 200809L

#include "ba.h"

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <sys/resource.h>
#include <getopt.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>

typedef struct {
    double wall, cpu;
} phase_clock;

static double process_cpu_ms(void) {
    struct timespec stamp;
    ba_require(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stamp) == 0, "process CPU clock");
    return (double)stamp.tv_sec * 1000.0 + (double)stamp.tv_nsec / 1000000.0;
}

static phase_clock phase_begin(void) {
    phase_clock clock;
    clock.cpu = process_cpu_ms();
    clock.wall = ba_now_ms();
    return clock;
}

static void phase_end(phase_clock clock, double *wall, double *cpu) {
    *wall = ba_now_ms() - clock.wall;
    *cpu = process_cpu_ms() - clock.cpu;
}

static void hex32(const unsigned char input[32], char output[65]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        output[2 * i] = digits[input[i] >> 4];
        output[2 * i + 1] = digits[input[i] & 15];
    }
    output[64] = '\0';
}

static uint64_t splitmix(uint64_t *s) {
    uint64_t z = (*s += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static uint64_t data_below(uint64_t *s, uint64_t n) {
    uint64_t x, lim = (uint64_t)(-n) % n;
    do {
        x = splitmix(s);
    } while (x < lim);
    return x % n;
}

static void shuffle(uint64_t *v, size_t n, uint64_t *seed) {
    for (size_t i = n; i > 1; i--) {
        size_t j = (size_t)data_below(seed, i);
        uint64_t x = v[i - 1];
        v[i - 1] = v[j];
        v[j] = x;
    }
}

static int approve(uint64_t id, void *arg) {
    (void)id;
    (void)arg;
    return 1;
}

static void checked(ba_status s, const char *phase) {
    if (s != BA_OK) {
        fprintf(stderr, "%s: %s\n", phase, ba_status_name(s));
        exit(2);
    }
}

static uint64_t parse(const char *s) {
    if (!s || *s < '0' || *s > '9') {
        fprintf(stderr, "Invalid integer: %s\n", s ? s : "(null)");
        exit(2);
    }
    errno = 0;
    char *end;
    unsigned long long n = strtoull(s, &end, 10);
    if (errno || *end) {
        fprintf(stderr, "Invalid integer: %s\n", s);
        exit(2);
    }
    return (uint64_t)n;
}

static void usage(const char *exe) {
    printf(
        "Usage: %s [options]\n"
        " --n N --m N --k K     set sizes and exact intersection (default 100/100/50)\n"
        " --capacity N          public client capacity N_C (default max(n,1))\n"
        " --server-capacity N   public server capacity N_S (default max(m,1))\n"
        " --max-value M         per-record value bound (default 1000)\n"
        " --universe U          attributes 1..U (default max(n+m-k,1))\n"
        " --degree D            coefficient count; degree <= D-1 (default 3)\n"
        " --mode optimized|reference  same protocol, different arithmetic (default optimized)\n"
        " --solver bsgs|kangaroo (default bsgs; kangaroo includes BSGS fallback)\n"
        " --repeat R --warmup W (default 5 and 1)\n"
        " --setup-mode fresh|reuse (default fresh); reuse initializes one key period before runs\n"
        " --recover-mode cold|prepared|prepared-fast (default cold); prepared modes require reuse\n"
        " --seed S              synthetic data only (default 1); crypto uses CSPRNG\n"
        " --memory-mib MB       DLP dictionary cap (default 256)\n"
        " --tame T --wild W --attempts J  kangaroo caps (full 4m/8m/4; fast 8m/2m/4)\n"
        " --params FILE         trusted Type-A parameters\n"
        " --csv FILE            write raw measured repetitions\n",
        exe);
}

int main(int argc, char **argv) {
    uint64_t n = 100, m = 100, k = 50, nc = 0, ns = 0, u = 0, max = 1000, d = 3, reps = 5,
             warmup = 1, seed = 1;
    const char *params = BA_DEFAULT_PARAMS, *csv = NULL;
    int optimized = 1, reuse_setup = 0, prepared_recover = 0, fast_recover = 0;
    ba_dlp_options opt = ba_dlp_defaults(BA_BSGS);
    static const struct option options[] = {{"n", 1, 0, 'n'},
                                            {"m", 1, 0, 'm'},
                                            {"k", 1, 0, 'k'},
                                            {"capacity", 1, 0, 'c'},
                                            {"server-capacity", 1, 0, 's'},
                                            {"max-value", 1, 0, 'v'},
                                            {"universe", 1, 0, 'u'},
                                            {"degree", 1, 0, 'd'},
                                            {"repeat", 1, 0, 'r'},
                                            {"warmup", 1, 0, 'w'},
                                            {"seed", 1, 0, 'e'},
                                            {"mode", 1, 0, 'o'},
                                            {"solver", 1, 0, 'l'},
                                            {"csv", 1, 0, 'f'},
                                            {"params", 1, 0, 'p'},
                                            {"memory-mib", 1, 0, 'b'},
                                            {"tame", 1, 0, 't'},
                                            {"wild", 1, 0, 'z'},
                                            {"attempts", 1, 0, 'a'},
                                            {"setup-mode", 1, 0, 'q'},
                                            {"recover-mode", 1, 0, 'R'},
                                            {"help", 0, 0, 'h'},
                                            {0, 0, 0, 0}};
    int ch;
    while ((ch = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (ch) {
            case 'R':
                ba_require(!strcmp(optarg, "cold") || !strcmp(optarg, "prepared") ||
                               !strcmp(optarg, "prepared-fast"),
                           "recover mode");
                prepared_recover = strcmp(optarg, "cold") != 0;
                fast_recover = !strcmp(optarg, "prepared-fast");
                break;
            case 'q':
                ba_require(!strcmp(optarg, "fresh") || !strcmp(optarg, "reuse"), "setup mode");
                reuse_setup = !strcmp(optarg, "reuse");
                break;
            case 'n':
                n = parse(optarg);
                break;
            case 'm':
                m = parse(optarg);
                break;
            case 'k':
                k = parse(optarg);
                break;
            case 'c':
                nc = parse(optarg);
                break;
            case 's':
                ns = parse(optarg);
                break;
            case 'v':
                max = parse(optarg);
                break;
            case 'u':
                u = parse(optarg);
                break;
            case 'd':
                d = parse(optarg);
                break;
            case 'r':
                reps = parse(optarg);
                break;
            case 'w':
                warmup = parse(optarg);
                break;
            case 'e':
                seed = parse(optarg);
                break;
            case 'o':
                if (!strcmp(optarg, "optimized"))
                    optimized = 1;
                else if (!strcmp(optarg, "reference"))
                    optimized = 0;
                else {
                    usage(argv[0]);
                    return 2;
                }
                break;
            case 'l':
                if (!strcmp(optarg, "bsgs"))
                    opt.solver = BA_BSGS;
                else if (!strcmp(optarg, "kangaroo"))
                    opt.solver = BA_KANGAROO;
                else {
                    usage(argv[0]);
                    return 2;
                }
                break;
            case 'f':
                csv = optarg;
                break;
            case 'p':
                params = optarg;
                break;
            case 'b': {
                uint64_t mb = parse(optarg);
                ba_require(mb <= SIZE_MAX / (1024u * 1024u), "memory cap overflow");
                opt.max_table_bytes = (size_t)mb * 1024u * 1024u;
                break;
            }
            case 't':
                opt.tame = parse(optarg);
                break;
            case 'z':
                opt.wild = parse(optarg);
                break;
            case 'a': {
                uint64_t a = parse(optarg);
                ba_require(a <= 64 && a >= 1, "attempt count 1..64");
                opt.attempts = (unsigned)a;
                break;
            }
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                return 2;
        }
    }
    ba_require(optind == argc, "unexpected positional argument");
    ba_require(n <= INT_MAX && m <= INT_MAX && k <= n && k <= m && n + m - k <= INT_MAX,
               "set sizes");
    if (!nc)
        nc = n ? n : 1;
    if (!ns)
        ns = m ? m : 1;
    if (!u)
        u = n + m - k ? n + m - k : 1;
    ba_require(nc >= n && ns >= m && u >= n + m - k && u <= INT_MAX && nc <= INT_MAX &&
                   ns <= INT_MAX,
               "public capacities/universe");
    ba_require(max < (uint64_t)INT64_MAX && nc <= ((uint64_t)INT64_MAX - 1) / (max ? max : 1) &&
                   d >= 1 && d <= 1024,
               "bound or polynomial degree");
    ba_require(reps >= 1 && reps <= 10000 && warmup <= 10000, "repetition limits");
    ba_require(!prepared_recover || reuse_setup, "prepared recovery requires setup-mode reuse");
    opt.strategy = fast_recover ? BA_DLP_EARLY_STOP : BA_DLP_FULL_BUDGET;
    const char *recover_mode = fast_recover       ? "prepared-fast"
                               : prepared_recover ? "prepared"
                                                  : "cold";
    ba_config cfg = {(size_t)u, (size_t)nc, (size_t)ns, (size_t)d, max, nc * max};
    FILE *f = csv ? fopen(csv, "wx") : NULL;
    ba_require(!csv || f != NULL, "CSV must be a new writable file");
    const char *header =
        "rep,n,m,k,universe,nc,ns,max_value,bound,degree,data_seed,mode,solver,setup_ms,authorize_client_ms,authorize_server_ms,intersect_ms,encapsulate_ms,aggregate_ms,recover_ms,total_ms,expected_sum,recovered_sum,fallback,attempts,baby_steps,giant_steps,tame_steps,wild_steps,dlp_peak_table_bytes,process_peak_rss_kib,logical_crypto_bytes,setup_mode,offline_setup_ms,setup_cpu_ms,authorize_client_cpu_ms,authorize_server_cpu_ms,intersect_cpu_ms,encapsulate_cpu_ms,aggregate_cpu_ms,recover_cpu_ms,total_cpu_ms,voluntary_context_switches,involuntary_context_switches,minor_faults,major_faults,period_fingerprint,session_context,recover_mode,offline_recover_ms,offline_recover_cpu_ms,offline_dlp_baby_steps,offline_dlp_tame_steps,offline_dlp_attempts,offline_dlp_table_bytes,offline_dlp_fingerprint\n";
    if (f)
        fputs(header, f);
    printf("BA-APSI C benchmark | PBC Type-A + P-256 | OpenSSL %s\n",
           OpenSSL_version(OPENSSL_VERSION));
    printf("params=%s\nn=%" PRIu64 " m=%" PRIu64 " k=%" PRIu64 " U=%" PRIu64 " N_C=%" PRIu64
           " M=%" PRIu64 " B=%" PRIu64 " d=%" PRIu64 "\n",
           params,
           n,
           m,
           k,
           u,
           nc,
           max,
           nc * max,
           d);
    printf("mode=%s solver=%s repeats=%" PRIu64 " warmup=%" PRIu64 "\n",
           optimized ? "optimized" : "reference",
           opt.solver == BA_BSGS ? "bsgs" : "kangaroo",
           reps,
           warmup);
    printf("Default Type-A-160/512 is a legacy benchmark suite, not a 128-bit security claim.\n");
    ba_random_init();
    ba_public p = {0};
    ba_authority a = {0};
    ba_recoverer rec = {0};
    double offline_setup_ms = 0, offline_setup_cpu_ms = 0;
    unsigned char fixed_period[32] = {0}, previous_context[32] = {0};
    if (reuse_setup) {
        phase_clock clock = phase_begin();
        checked(ba_setup(&p, &a, &rec, params, &cfg), "Offline Setup");
        phase_end(clock, &offline_setup_ms, &offline_setup_cpu_ms);
        memcpy(fixed_period, p.period, 32);
    }
    printf("setup_mode=%s offline_setup_ms=%.6f offline_setup_cpu_ms=%.6f\n",
           reuse_setup ? "reuse" : "fresh",
           offline_setup_ms,
           offline_setup_cpu_ms);
    ba_dlp_prepared *recovery = NULL;
    ba_dlp_stats offline_dlp = {0};
    double offline_recover_ms = 0, offline_recover_cpu_ms = 0;
    unsigned char recovery_id[32] = {0};
    if (prepared_recover) {
        phase_clock clock = phase_begin();
        checked(ba_dlp_prepare(&p.ec, 0, (int64_t)cfg.bound, &opt, &recovery, &offline_dlp),
                "Offline Recover preprocessing");
        phase_end(clock, &offline_recover_ms, &offline_recover_cpu_ms);
        ba_dlp_prepared_id(recovery, recovery_id);
    }
    printf(
        "recover_mode=%s offline_recover_ms=%.6f offline_recover_cpu_ms=%.6f offline_table_bytes=%zu\n",
        recover_mode,
        offline_recover_ms,
        offline_recover_cpu_ms,
        offline_dlp.peak_table_bytes);
    double sums[7] = {0}, total_sum = 0;
    uint64_t fallback_count = 0;
    for (uint64_t run = 0; run < reps + warmup; run++) {
        uint64_t data_seed = seed + (run < warmup ? run : run - warmup), state = data_seed;
        uint64_t *cids = ba_alloc(n, sizeof(uint64_t)), *sids = ba_alloc(m, sizeof(uint64_t)),
                 *values = ba_alloc(n, sizeof(uint64_t));
        for (uint64_t i = 0; i < n; i++)
            cids[i] = i + 1;
        for (uint64_t i = 0; i < m; i++)
            sids[i] = i < k ? i + 1 : n + i - k + 1;
        shuffle(cids, n, &state);
        shuffle(sids, m, &state);
        uint64_t expected = 0;
        for (uint64_t i = 0; i < n; i++) {
            values[i] = data_below(&state, max + 1);
            if (cids[i] <= k)
                expected += values[i];
        }
        ba_certificates cc, sc;
        ba_request request;
        ba_response response;
        ba_matches match;
        ba_payloads payload;
        ba_ciphertext aggregate;
        ba_dlp_stats stats;
        uint64_t answer = UINT64_MAX;
        double ms[7], cpu_ms[7];
        struct rusage run_before;
        ba_require(getrusage(RUSAGE_SELF, &run_before) == 0, "initial run usage");
        phase_clock clock = phase_begin();
        if (!reuse_setup)
            checked(ba_setup(&p, &a, &rec, params, &cfg), "Setup");
        unsigned char sid[32], ctx[32];
        ba_require(RAND_bytes(sid, 32) == 1, "session randomness");
        ba_context(&p, "client", "server", sid, ctx);
        phase_end(clock, &ms[0], &cpu_ms[0]);
        if (reuse_setup)
            ba_require(!memcmp(fixed_period, p.period, 32), "reused parameter period");
        if (run)
            ba_require(memcmp(previous_context, ctx, 32) != 0, "fresh session context");
        memcpy(previous_context, ctx, 32);
        clock = phase_begin();
        checked(ba_authorize(&p, &a, cids, n, approve, NULL, &cc), "Authorize client");
        phase_end(clock, &ms[1], &cpu_ms[1]);
        clock = phase_begin();
        checked(ba_authorize(&p, &a, sids, m, approve, NULL, &sc), "Authorize server");
        phase_end(clock, &ms[2], &cpu_ms[2]);
        clock = phase_begin();
        ba_client_begin(&p, ctx, &request);
        checked(ba_server_respond(&p, &sc, &request, ctx, optimized, &response), "Server respond");
        checked(ba_client_match(&p, &cc, &request, &response, optimized, &match), "Client match");
        phase_end(clock, &ms[3], &cpu_ms[3]);
        ba_require(match.n == k, "intersection cardinality oracle");
        unsigned char *seen = ba_alloc(n, 1);
        for (size_t i = 0; i < match.n; i++) {
            ba_match *x = &match.items[i];
            ba_require(x->client_index < n && x->response_index < m, "match indices");
            uint64_t id = cids[x->client_index];
            ba_require(!seen[x->client_index] && id <= k &&
                           id == sids[response.source[x->response_index]],
                       "exact intersection oracle");
            seen[x->client_index] = 1;
        }
        for (size_t i = 0; i < n; i++)
            ba_require((seen[i] != 0) == (cids[i] <= k), "missing/extra matches");
        free(seen);
        clock = phase_begin();
        checked(ba_encapsulate(&p, &cc, values, &match, &payload), "Encapsulate");
        phase_end(clock, &ms[4], &cpu_ms[4]);
        clock = phase_begin();
        checked(ba_blind_aggregate(&p, &response, &payload, &aggregate), "BlindAggregate");
        phase_end(clock, &ms[5], &cpu_ms[5]);
        clock = phase_begin();
        checked(prepared_recover
                    ? ba_recover_prepared(&p, &rec, &aggregate, recovery, &answer, &stats)
                    : ba_recover(&p, &rec, &aggregate, &opt, &answer, &stats),
                "Recover");
        phase_end(clock, &ms[6], &cpu_ms[6]);
        ba_require(answer == expected, "exact sum oracle");
        double total = 0;
        for (size_t i = 0; i < 7; i++)
            total += ms[i];
        struct rusage ru;
        ba_require(getrusage(RUSAGE_SELF, &ru) == 0, "getrusage");
        uint64_t wire = 2 * (uint64_t)pairing_length_in_bytes_G1(p.pairing) +
                        m * (uint64_t)pairing_length_in_bytes_GT(p.pairing) + k * (66 + 8) + 66;
        if (run >= warmup) {
            for (size_t i = 0; i < 7; i++) {
                sums[i] += ms[i];
            }
            total_sum += total;
            fallback_count += (unsigned)stats.fallback;
            printf("rep=%" PRIu64 " exact matches=%zu sum=%" PRIu64
                   " total=%.3f ms recover=%.3f ms fallback=%d OK\n",
                   run - warmup,
                   match.n,
                   answer,
                   total,
                   ms[6],
                   stats.fallback);
            if (f) {
                fprintf(f,
                        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
                        ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%s,%s",
                        run - warmup,
                        n,
                        m,
                        k,
                        u,
                        nc,
                        ns,
                        max,
                        nc * max,
                        d,
                        data_seed,
                        optimized ? "optimized" : "reference",
                        opt.solver == BA_BSGS ? "bsgs" : "kangaroo");
                for (size_t i = 0; i < 7; i++)
                    fprintf(f, ",%.6f", ms[i]);
                fprintf(f,
                        ",%.6f,%" PRIu64 ",%" PRIu64 ",%d,%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64
                        ",%" PRIu64 ",%zu,%ld,%" PRIu64,
                        total,
                        expected,
                        answer,
                        stats.fallback,
                        stats.attempts,
                        stats.baby_steps,
                        stats.giant_steps,
                        stats.tame_steps,
                        stats.wild_steps,
                        stats.peak_table_bytes,
                        ru.ru_maxrss,
                        wire);
                fprintf(f, ",%s,%.6f", reuse_setup ? "reuse" : "fresh", offline_setup_ms);
                double cpu_total = 0;
                for (size_t i = 0; i < 7; i++) {
                    fprintf(f, ",%.6f", cpu_ms[i]);
                    cpu_total += cpu_ms[i];
                }
                char period_hex[65], context_hex[65];
                hex32(p.period, period_hex);
                hex32(ctx, context_hex);
                fprintf(f,
                        ",%.6f,%ld,%ld,%ld,%ld,%s,%s",
                        cpu_total,
                        ru.ru_nvcsw - run_before.ru_nvcsw,
                        ru.ru_nivcsw - run_before.ru_nivcsw,
                        ru.ru_minflt - run_before.ru_minflt,
                        ru.ru_majflt - run_before.ru_majflt,
                        period_hex,
                        context_hex);
                char recovery_hex[65];
                hex32(recovery_id, recovery_hex);
                fprintf(f,
                        ",%s,%.6f,%.6f,%" PRIu64 ",%" PRIu64 ",%u,%zu,%s\n",
                        recover_mode,
                        offline_recover_ms,
                        offline_recover_cpu_ms,
                        offline_dlp.baby_steps,
                        offline_dlp.tame_steps,
                        offline_dlp.attempts,
                        offline_dlp.peak_table_bytes,
                        recovery_hex);
                fflush(f);
            }
        }
        ba_payloads_clear(&payload);
        ba_matches_clear(&match);
        ba_response_clear(&response);
        ba_request_clear(&request);
        ba_certificates_clear(&cc);
        ba_certificates_clear(&sc);
        if (!reuse_setup)
            ba_setup_clear(&p, &a, &rec);
        free(cids);
        free(sids);
        free(values);
    }
    ba_dlp_prepared_clear(recovery);
    if (reuse_setup)
        ba_setup_clear(&p, &a, &rec);
    const char *names[] = {"Setup (incl. parameter load/validation)",
                           "Authorize client",
                           "Authorize server",
                           "Intersect",
                           "Encapsulate",
                           "BlindAggregate",
                           "Recover (cold table)"};
    if (reuse_setup)
        names[0] = "SessionSetup (random session + context)";
    if (prepared_recover)
        names[6] = "Recover online (decrypt + solve + verify)";
    for (size_t i = 0; i < 7; i++)
        printf("%-40s mean_ms=%.3f\n", names[i], sums[i] / (double)reps);
    printf("phase_sum mean_ms=%.3f fallback=%" PRIu64 "/%" PRIu64 "\n",
           total_sum / (double)reps,
           fallback_count,
           reps);
    if (f)
        ba_require(fclose(f) == 0, "close CSV");
    return 0;
}
