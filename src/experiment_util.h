#ifndef EXPERIMENT_UTIL_H
#define EXPERIMENT_UTIL_H

#include "ba.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

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

#endif
