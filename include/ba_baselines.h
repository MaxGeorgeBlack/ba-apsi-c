#ifndef BA_BASELINES_H
#define BA_BASELINES_H

#include "ba.h"

typedef enum { BASE_SORT = 0, BASE_HASH, BASE_CUCKOO, BASE_BLOOM } ba_baseline;

typedef struct {
    double build_ms, probe_ms;
    size_t table_bytes, stash_size;
    uint64_t filter_passes;
} ba_baseline_stats;

/* Plaintext uint64 lookup kernels, NOT secure PSI protocols. Inputs are sets.
 * hits are client-position bits; every reported result is exact. */
ba_status ba_baseline_run(ba_baseline method,
                          const uint64_t *client,
                          size_t n,
                          const uint64_t *server,
                          size_t m,
                          unsigned char *hits,
                          ba_baseline_stats *stats);

#endif
