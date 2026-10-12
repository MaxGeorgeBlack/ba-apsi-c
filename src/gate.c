#include "experiment_util.h"

/* Text pipe for a LOCAL benchmark only: first two sizes, then client and server
 * attribute IDs. Never accepts memory content. Each query has a fresh session. */
int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: ba_gate PARAMS UNIVERSE\n");
        return 2;
    }
    size_t u = (size_t)ex_parse(argv[2]);
    ba_require(u && u <= 10000000, "gate universe");
    ba_random_init();
    ba_config cfg = {u, u, u, 3, 0, 0};
    ba_public p;
    ba_authority a;
    ba_recoverer r;
    ex_check(ba_setup(&p, &a, &r, argv[1], &cfg), "gate setup");
    puts("READY");
    fflush(stdout);
    size_t n, m;
    while (scanf("%zu %zu", &n, &m) == 2) {
        ba_require(n <= u && m <= u, "gate counts");
        uint64_t *c = ba_alloc(n, 8), *s = ba_alloc(m, 8);
        for (size_t i = 0; i < n; i++)
            ba_require(scanf("%" SCNu64, &c[i]) == 1, "client ID");
        for (size_t j = 0; j < m; j++)
            ba_require(scanf("%" SCNu64, &s[j]) == 1, "server ID");
        ba_certificates cc, sc;
        double start = ba_now_ms();
        ex_check(ba_authorize(&p, &a, c, n, ex_approve, NULL, &cc), "client authorization");
        ex_check(ba_authorize(&p, &a, s, m, ex_approve, NULL, &sc), "server authorization");
        double auth = ba_now_ms() - start;
        unsigned char sid[32], ctx[32];
        ba_require(RAND_bytes(sid, 32) == 1, "session");
        ba_context(&p, "requester", "memory-store", sid, ctx);
        ba_request request;
        ba_response response;
        ba_matches hits;
        start = ba_now_ms();
        ba_client_begin(&p, ctx, &request);
        ex_check(ba_server_respond(&p, &sc, &request, ctx, 1, &response), "server");
        ex_check(ba_client_match(&p, &cc, &request, &response, 1, &hits), "client");
        double intersect = ba_now_ms() - start;
        printf("OK %.6f %.6f %zu", auth, intersect, hits.n);
        for (size_t i = 0; i < hits.n; i++)
            printf(" %" PRIu64, c[hits.items[i].client_index]);
        putchar('\n');
        fflush(stdout);
        ba_matches_clear(&hits);
        ba_response_clear(&response);
        ba_request_clear(&request);
        ba_certificates_clear(&cc);
        ba_certificates_clear(&sc);
        free(c);
        free(s);
    }
    ba_require(feof(stdin), "malformed gate request");
    ba_setup_clear(&p, &a, &r);
    return 0;
}
