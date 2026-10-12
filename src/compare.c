#include "experiment_util.h"
#include "ba_baselines.h"

#include <sys/resource.h>

int main(int argc, char **argv) {
    if (argc != 8) {
        fprintf(stderr, "Usage: ba_compare PARAMS N M K REPEATS WARMUP CSV\n");
        return 2;
    }
    size_t n = (size_t)ex_parse(argv[2]), m = (size_t)ex_parse(argv[3]),
           k = (size_t)ex_parse(argv[4]);
    uint64_t reps = ex_parse(argv[5]), warm = ex_parse(argv[6]);
    ba_require(n <= 10000000 && m <= 10000000 && k <= n && k <= m && reps && reps <= 1000 &&
                   warm <= 1000,
               "comparison limits");
    FILE *f = fopen(argv[7], "wx");
    ba_require(f != NULL, "new comparison CSV");
    setvbuf(stdout, NULL, _IOLBF, 0);
    fputs(
        "method,n,m,k,rep,setup_ms,authorize_ms,server_or_build_ms,client_or_probe_ms,intersect_ms,table_bytes,stash_size,filter_passes,process_peak_rss_kib,validation\n",
        f);
    fflush(f);
    uint64_t *c = ba_alloc(n, 8), *s = ba_alloc(m, 8), seed = 20260928;
    unsigned char *hits = ba_alloc(n, 1);
    for (size_t i = 0; i < n; i++)
        c[i] = i + 1;
    for (size_t j = 0; j < m; j++)
        s[j] = j < k ? j + 1 : n + j - k + 1;
    ex_shuffle(c, n, &seed);
    ex_shuffle(s, m, &seed);
    ba_random_init();
    ba_config cfg = {n + m - k ? n + m - k : 1, n ? n : 1, m ? m : 1, 3, 0, 0};
    ba_public p;
    ba_authority a;
    ba_recoverer r;
    printf("SETUP n=%zu m=%zu U=%zu\n", n, m, cfg.universe);
    double start = ba_now_ms();
    ex_check(ba_setup(&p, &a, &r, argv[1], &cfg), "Setup");
    double setup = ba_now_ms() - start;
    printf("AUTHORIZE setup_ms=%.3f\n", setup);
    ba_certificates cc, sc;
    start = ba_now_ms();
    ex_check(ba_authorize(&p, &a, c, n, ex_approve, NULL, &cc), "Authorize C");
    ex_check(ba_authorize(&p, &a, s, m, ex_approve, NULL, &sc), "Authorize S");
    double auth = ba_now_ms() - start;
    printf("INTERSECT auth_ms=%.3f\n", auth);
    const char *names[] = {"sort-merge", "hash-probe", "cuckoo-probe", "bloom-prefilter"};
    for (unsigned run = 0; run < reps + warm; run++) {
        unsigned char sid[32], ctx[32];
        ba_require(RAND_bytes(sid, 32) == 1, "session");
        ba_context(&p, "compare-client", "compare-server", sid, ctx);
        ba_request request;
        ba_response response;
        ba_matches matches;
        start = ba_now_ms();
        ba_client_begin(&p, ctx, &request);
        ex_check(ba_server_respond(&p, &sc, &request, ctx, 1, &response), "Server");
        double server = ba_now_ms() - start;
        start = ba_now_ms();
        ex_check(ba_client_match(&p, &cc, &request, &response, 1, &matches), "Client");
        double client = ba_now_ms() - start;
        memset(hits, 0, n);
        for (size_t i = 0; i < matches.n; i++) {
            ba_match *hit = &matches.items[i];
            ba_require(c[hit->client_index] == s[response.source[hit->response_index]],
                       "mapping oracle");
            hits[hit->client_index] = 1;
        }
        ba_require(matches.n == k, "cardinality oracle");
        for (size_t i = 0; i < n; i++)
            ba_require((hits[i] != 0) == (c[i] <= k), "exact oracle");
        struct rusage ru;
        getrusage(RUSAGE_SELF, &ru);
        if (run >= warm) {
            fprintf(f,
                    "BA-APSI,%zu,%zu,%zu,%u,%.6f,%.6f,%.6f,%.6f,%.6f,0,0,0,%ld,PASS\n",
                    n,
                    m,
                    k,
                    (unsigned)(run - warm),
                    setup,
                    auth,
                    server,
                    client,
                    server + client,
                    ru.ru_maxrss);
            fflush(f);
        }
        ba_matches_clear(&matches);
        ba_response_clear(&response);
        ba_request_clear(&request);
        /* All baseline construction is redone inside its timed region. */
        for (unsigned method = 0; method < 4; method++) {
            ba_baseline_stats st;
            ex_check(ba_baseline_run((ba_baseline)method, c, n, s, m, hits, &st), "baseline");
            for (size_t i = 0; i < n; i++)
                ba_require((hits[i] != 0) == (c[i] <= k), "baseline exact oracle");
            getrusage(RUSAGE_SELF, &ru);
            if (run >= warm) {
                fprintf(f,
                        "%s,%zu,%zu,%zu,%u,0,0,%.6f,%.6f,%.6f,%zu,%zu,%" PRIu64 ",%ld,PASS\n",
                        names[method],
                        n,
                        m,
                        k,
                        (unsigned)(run - warm),
                        st.build_ms,
                        st.probe_ms,
                        st.build_ms + st.probe_ms,
                        st.table_bytes,
                        st.stash_size,
                        st.filter_passes,
                        ru.ru_maxrss);
                fflush(f);
            }
        }
        printf("DONE run=%u warmup=%d BA_ms=%.3f exact=%zu\n", run, run < warm, server + client, k);
    }
    ba_certificates_clear(&cc);
    ba_certificates_clear(&sc);
    ba_setup_clear(&p, &a, &r);
    free(c);
    free(s);
    free(hits);
    ba_require(fclose(f) == 0, "CSV close");
    return 0;
}
