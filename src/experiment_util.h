#ifndef EXPERIMENT_UTIL_H
#define EXPERIMENT_UTIL_H

#include "ba.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/rand.h>

static inline uint64_t ex_parse(const char *s) {
    ba_require(s && *s >= '0' && *s <= '9', "nonnegative integer required");
    errno = 0;
    char *end;
    uint64_t x = strtoull(s, &end, 10);
    ba_require(!errno && !*end, "invalid integer");
    return x;
}

static inline void ex_check(ba_status s, const char *where) {
    if (s != BA_OK) {
        fprintf(stderr, "%s: %s\n", where, ba_status_name(s));
        exit(2);
    }
}

static inline int ex_approve(uint64_t id, void *p) {
    (void)id;
    (void)p;
    return 1;
}

static inline uint64_t ex_next(uint64_t *state) {
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static inline void ex_shuffle(uint64_t *a, size_t n, uint64_t *state) {
    for (size_t i = n; i > 1; i--) {
        uint64_t lim = (uint64_t)(-(uint64_t)i) % i, x;
        do {
            x = ex_next(state);
        } while (x < lim);
        size_t j = (size_t)(x % i);
        uint64_t t = a[i - 1];
        a[i - 1] = a[j];
        a[j] = t;
    }
}

#endif
