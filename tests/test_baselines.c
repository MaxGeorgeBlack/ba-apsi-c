#include "ba_baselines.h"

#include <stdlib.h>
#include <string.h>
#define CHECK(x) ba_require((x), #x)

int main(void) {
    size_t checks = 0;
    for (size_t trial = 0; trial < 30; trial++) {
        size_t m = trial * 43, n = trial * 7;
        uint64_t *s = ba_alloc(m, 8), *c = ba_alloc(n, 8);
        unsigned char *oracle = ba_alloc(n, 1), *hits = ba_alloc(n, 1);
        for (size_t j = 0; j < m; j++)
            s[j] = (j * 37) ^ UINT64_C(0x8000000000000000);
        for (size_t i = 0; i < n; i++)
            c[i] = i % 3 && m ? s[(i * 17) % m] : i;
        for (size_t i = 0; i < n; i++)
            for (size_t j = 0; j < m; j++)
                if (c[i] == s[j])
                    oracle[i] = 1;
        for (unsigned method = 0; method < 4; method++) {
            ba_baseline_stats st;
            CHECK(ba_baseline_run((ba_baseline)method, c, n, s, m, hits, &st) == BA_OK);
            CHECK(!memcmp(hits, oracle, n));
            checks++;
        }
        free(s);
        free(c);
        free(oracle);
        free(hits);
    }
    uint64_t s[] = {0, UINT64_MAX, 4}, c[] = {UINT64_MAX, 1, 0, 4};
    unsigned char hits[4], expect[] = {1, 0, 1, 1};
    for (unsigned method = 0; method < 4; method++) {
        ba_baseline_stats st;
        CHECK(ba_baseline_run((ba_baseline)method, c, 4, s, 3, hits, &st) == BA_OK);
        CHECK(!memcmp(hits, expect, 4));
        checks++;
    }
    printf(
        "PASS %zu baseline differential cases, including empty sets, full uint64 IDs, Bloom exact verification and cuckoo stash lookup\n",
        checks);
    return 0;
}
