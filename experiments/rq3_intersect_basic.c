/* Standalone set-membership intersection: no protocol or cryptographic library.
 * Counters are collected inside timed loops; times describe instrumented kernels.
 * Each output byte identifies whether the corresponding C key occurs in S.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    uint64_t key;
    size_t index;
} entry;

typedef struct {
    double build_ms, probe_ms;
    uint64_t build_work, probe_work, hash_calls;
    uint64_t stash_size, stash_probes, filter_passes, false_positives, index_checks;
    int rejected;
} measurement;

static void require(int ok, const char *message) {
    if (!ok) {
        fprintf(stderr, "ERROR: %s\n", message);
        exit(EXIT_FAILURE);
    }
}

static void *allocate(size_t count, size_t width) {
    require(width && count <= SIZE_MAX / width, "allocation overflow");
    void *p = calloc(count ? count : 1, width);
    require(p != NULL, "allocation failed");
    return p;
}

static double now_ms(void) {
    struct timespec ts;
    require(clock_gettime(CLOCK_MONOTONIC, &ts) == 0, "clock_gettime failed");
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

/* A bijection on uint64_t: distinct synthetic IDs stay distinct. */
static uint64_t mix(uint64_t x) {
    x ^= x >> 30;
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}

static uint64_t next_random(uint64_t *state) {
    *state += UINT64_C(0x9e3779b97f4a7c15);
    return mix(*state);
}

static void shuffle(uint64_t *keys, unsigned char *truth, size_t count, uint64_t *state) {
    for (size_t i = count; i > 1; i--) {
        uint64_t limit = (uint64_t)(-(uint64_t)i) % i, random;
        do {
            random = next_random(state);
        } while (random < limit);
        size_t j = (size_t)(random % i);
        uint64_t key = keys[i - 1];
        keys[i - 1] = keys[j];
        keys[j] = key;
        if (truth) {
            unsigned char flag = truth[i - 1];
            truth[i - 1] = truth[j];
            truth[j] = flag;
        }
    }
}

static void generate(
    uint64_t *c, size_t n, uint64_t *s, size_t m, size_t k, uint64_t seed, unsigned char *truth) {
    for (size_t i = 0; i < n; i++) {
        c[i] = mix(seed + i);
        truth[i] = (unsigned char)(i < k);
    }
    for (size_t j = 0; j < m; j++)
        s[j] = mix(seed + (j < k ? j : n + j - k));
    shuffle(c, truth, n, &seed);
    shuffle(s, NULL, m, &seed);
}

/* Worst case O(n*m); stop at the first exact match for each client key. */
static measurement nested_loop(
    const uint64_t *c, size_t n, const uint64_t *s, size_t m, unsigned char *hits) {
    measurement r = {0};
    double start = now_ms();
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < m; j++) {
            r.probe_work++;
            if (c[i] == s[j]) {
                hits[i] = 1;
                break;
            }
        }
    }
    r.probe_ms = now_ms() - start;
    return r;
}

/* Explicit mergesort keeps the sorting complexity independent of libc qsort. */
static void merge_sort(entry *items, entry *scratch, size_t count, uint64_t *comparisons) {
    if (count < 2)
        return;
    size_t middle = count / 2;
    merge_sort(items, scratch, middle, comparisons);
    merge_sort(items + middle, scratch + middle, count - middle, comparisons);
    size_t i = 0, j = middle, out = 0;
    while (i < middle && j < count) {
        (*comparisons)++;
        scratch[out++] = items[i].key <= items[j].key ? items[i++] : items[j++];
    }
    while (i < middle)
        scratch[out++] = items[i++];
    while (j < count)
        scratch[out++] = items[j++];
    memcpy(items, scratch, count * sizeof *items);
}

/* Sorting is included: O(n log n + m log m + n + m). */
static measurement sort_merge(
    const uint64_t *c, size_t n, const uint64_t *s, size_t m, unsigned char *hits) {
    measurement r = {0};
    double start = now_ms();
    entry *left = allocate(n, sizeof *left), *right = allocate(m, sizeof *right);
    entry *scratch = allocate(n > m ? n : m, sizeof *scratch);
    for (size_t i = 0; i < n; i++)
        left[i] = (entry){c[i], i};
    for (size_t j = 0; j < m; j++)
        right[j] = (entry){s[j], j};
    merge_sort(left, scratch, n, &r.build_work);
    merge_sort(right, scratch, m, &r.build_work);
    r.build_ms = now_ms() - start;

    start = now_ms();
    size_t i = 0, j = 0;
    while (i < n && j < m) {
        r.probe_work++;
        if (left[i].key == right[j].key) {
            hits[left[i].index] = 1;
            i++;
        } else if (left[i].key < right[j].key) {
            i++;
        } else {
            j++;
        }
    }
    r.probe_ms = now_ms() - start;
    free(scratch);
    free(right);
    free(left);
    return r;
}

static size_t find_slot(const uint64_t *keys,
                        const unsigned char *used,
                        size_t capacity,
                        uint64_t key,
                        uint64_t *visits) {
    size_t slot = (size_t)mix(key) & (capacity - 1);
    for (;;) {
        (*visits)++;
        if (!used[slot] || keys[slot] == key)
            return slot;
        slot = (slot + 1) & (capacity - 1);
    }
}

/* Linear probing, load <= 1/2. Expected O(n+m), not a worst-case guarantee. */
static measurement hash_probe(
    const uint64_t *c, size_t n, const uint64_t *s, size_t m, unsigned char *hits) {
    measurement r = {0};
    double start = now_ms();
    size_t capacity = 2;
    while (capacity < 2 * m)
        capacity *= 2;
    uint64_t *keys = allocate(capacity, sizeof *keys);
    unsigned char *used = allocate(capacity, sizeof *used);
    for (size_t j = 0; j < m; j++) {
        size_t slot = find_slot(keys, used, capacity, s[j], &r.build_work);
        used[slot] = 1;
        keys[slot] = s[j];
    }
    r.build_ms = now_ms() - start;

    start = now_ms();
    for (size_t i = 0; i < n; i++) {
        size_t slot = find_slot(keys, used, capacity, c[i], &r.probe_work);
        hits[i] = used[slot];
    }
    r.probe_ms = now_ms() - start;
    r.hash_calls = n + m;
    free(used);
    free(keys);
    return r;
}

/* Structural model of ba_client_match AFTER token generation. Each uint64 key
 * stands for an exact equality label, not a serialized GT point. Retain client
 * uniqueness, server multiplicities, response positions and reuse rejection.
 * No cryptographic cost or security property is represented by this model.
 */
static measurement ba_tag_match(
    const uint64_t *c, size_t n, const uint64_t *s, size_t m, unsigned char *hits) {
    measurement r = {0};
    double start = now_ms();
    size_t capacity = 2, client_capacity = 2;
    while (capacity < 2 * m)
        capacity *= 2;
    while (client_capacity < 2 * n)
        client_capacity *= 2;
    uint64_t *keys = allocate(capacity, sizeof *keys);
    size_t *counts = allocate(capacity, sizeof *counts);
    size_t *positions = allocate(capacity, sizeof *positions);
    unsigned char *occupied = allocate(capacity, 1), *used_response = allocate(m, 1);
    uint64_t *client_keys = allocate(client_capacity, sizeof *client_keys);
    unsigned char *client_seen = allocate(client_capacity, 1);

    for (size_t i = 0; i < n; i++) {
        size_t slot = find_slot(client_keys, client_seen, client_capacity, c[i], &r.build_work);
        r.hash_calls++;
        if (client_seen[slot]) {
            r.rejected = 1;
            break;
        }
        client_seen[slot] = 1;
        client_keys[slot] = c[i];
    }
    if (!r.rejected) {
        for (size_t j = 0; j < m; j++) {
            size_t slot = find_slot(keys, occupied, capacity, s[j], &r.build_work);
            r.hash_calls++;
            keys[slot] = s[j];
            occupied[slot] = 1;
            counts[slot]++;
            positions[slot] = j;
        }
    }
    r.build_ms = now_ms() - start;

    start = now_ms();
    if (!r.rejected) {
        for (size_t i = 0; i < n; i++) {
            size_t slot = find_slot(keys, occupied, capacity, c[i], &r.probe_work);
            r.hash_calls++;
            if (counts[slot] > 1) {
                r.rejected = 1;
                break;
            }
            if (counts[slot]) {
                size_t j = positions[slot];
                r.index_checks++;
                if (used_response[j]) {
                    r.rejected = 1;
                    break;
                }
                require(s[j] == c[i], "BA label response index");
                used_response[j] = 1;
                hits[i] = 1;
            }
        }
    }
    r.probe_ms = now_ms() - start;
    if (r.rejected)
        memset(hits, 0, n);
    free(client_seen);
    free(client_keys);
    free(used_response);
    free(occupied);
    free(positions);
    free(counts);
    free(keys);
    return r;
}

static size_t cuckoo_slot(uint64_t key, size_t capacity, unsigned side) {
    uint64_t salt = side ? UINT64_C(0x9e3779b97f4a7c15) : UINT64_C(0x243f6a8885a308d3);
    return side * capacity + ((size_t)mix(key ^ salt) & (capacity - 1));
}

/* Two tables, each >= 2*m slots. Bounded eviction; every overflow is retained
 * in an exact stash. With stash size z, probing is O(n*(1+z)).
 */
static measurement cuckoo_probe(
    const uint64_t *c, size_t n, const uint64_t *s, size_t m, unsigned char *hits) {
    measurement r = {0};
    double start = now_ms();
    size_t capacity = 2;
    while (capacity < 2 * m)
        capacity *= 2;
    uint64_t *keys = allocate(2 * capacity, sizeof *keys), *stash = allocate(m, sizeof *stash);
    unsigned char *used = allocate(2 * capacity, 1);
    size_t stash_count = 0;
    for (size_t j = 0; j < m; j++) {
        int duplicate = 0;
        for (unsigned side = 0; side < 2; side++) {
            size_t slot = cuckoo_slot(s[j], capacity, side);
            r.hash_calls++;
            r.build_work++;
            if (used[slot] && keys[slot] == s[j]) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate)
            continue;
        uint64_t key = s[j];
        unsigned side = 0;
        int inserted = 0;
        for (unsigned kick = 0; kick < 512; kick++) {
            size_t slot = cuckoo_slot(key, capacity, side);
            r.hash_calls++;
            r.build_work++;
            if (!used[slot]) {
                keys[slot] = key;
                used[slot] = 1;
                inserted = 1;
                break;
            }
            uint64_t displaced = keys[slot];
            keys[slot] = key;
            key = displaced;
            side ^= 1;
        }
        if (!inserted)
            stash[stash_count++] = key;
    }
    r.stash_size = stash_count;
    r.build_ms = now_ms() - start;

    start = now_ms();
    for (size_t i = 0; i < n; i++) {
        for (unsigned side = 0; side < 2; side++) {
            size_t slot = cuckoo_slot(c[i], capacity, side);
            r.hash_calls++;
            r.probe_work++;
            if (used[slot] && keys[slot] == c[i]) {
                hits[i] = 1;
                break;
            }
        }
        for (size_t j = 0; j < stash_count && !hits[i]; j++) {
            r.stash_probes++;
            r.probe_work++;
            if (stash[j] == c[i])
                hits[i] = 1;
        }
    }
    r.probe_ms = now_ms() - start;
    free(stash);
    free(used);
    free(keys);
    return r;
}

static int binary_contains(const entry *sorted, size_t count, uint64_t key, uint64_t *work) {
    size_t left = 0, right = count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        (*work)++;
        if (sorted[middle].key == key)
            return 1;
        if (sorted[middle].key < key)
            left = middle + 1;
        else
            right = middle;
    }
    return 0;
}

/* 12 bits/record, 8 derived positions. Every positive is checked exactly in S.
 * bit_override is used ONLY by self-tests to force false-positive candidates.
 */
static measurement bloom_run(const uint64_t *c,
                             size_t n,
                             const uint64_t *s,
                             size_t m,
                             unsigned char *hits,
                             size_t bit_override) {
    measurement r = {0};
    double start = now_ms();
    size_t bits = bit_override ? bit_override : (m ? 12 * m : 64);
    unsigned char *filter = allocate((bits + 7) / 8, 1);
    entry *sorted = allocate(m, sizeof *sorted), *scratch = allocate(m, sizeof *scratch);
    for (size_t j = 0; j < m; j++) {
        sorted[j] = (entry){s[j], j};
        uint64_t a = mix(s[j]), b = mix(s[j] ^ UINT64_C(0xa0761d6478bd642f)) | 1;
        r.hash_calls += 2;
        for (unsigned h = 0; h < 8; h++) {
            size_t at = (size_t)((a + h * b) % bits);
            filter[at / 8] |= (unsigned char)(1u << (at % 8));
            r.build_work++;
        }
    }
    merge_sort(sorted, scratch, m, &r.build_work);
    r.build_ms = now_ms() - start;

    start = now_ms();
    for (size_t i = 0; i < n; i++) {
        uint64_t a = mix(c[i]), b = mix(c[i] ^ UINT64_C(0xa0761d6478bd642f)) | 1;
        r.hash_calls += 2;
        int possible = 1;
        for (unsigned h = 0; h < 8; h++) {
            size_t at = (size_t)((a + h * b) % bits);
            r.probe_work++;
            if (!(filter[at / 8] & (1u << (at % 8)))) {
                possible = 0;
                break;
            }
        }
        if (possible) {
            r.filter_passes++;
            hits[i] = (unsigned char)binary_contains(sorted, m, c[i], &r.probe_work);
            r.false_positives += !hits[i];
        }
    }
    r.probe_ms = now_ms() - start;
    free(scratch);
    free(sorted);
    free(filter);
    return r;
}

static measurement bloom_prefilter(
    const uint64_t *c, size_t n, const uint64_t *s, size_t m, unsigned char *hits) {
    return bloom_run(c, n, s, m, hits, 0);
}

typedef measurement (*intersect_fn)(
    const uint64_t *, size_t, const uint64_t *, size_t, unsigned char *);

enum { BA_TAG, SORT_MERGE, HASH_PROBE, CUCKOO_PROBE, BLOOM_PREFILTER, NESTED_LOOP, METHOD_COUNT };

static const intersect_fn methods[] = {
    ba_tag_match, sort_merge, hash_probe, cuckoo_probe, bloom_prefilter, nested_loop};
static const char *names[] = {"ba-apsi-tag-match",
                              "sort-merge",
                              "hash-probe",
                              "cuckoo-probe",
                              "bloom-prefilter",
                              "nested-loop"};
static const char *units[] = {"slot_visits",
                              "key_comparisons",
                              "slot_visits",
                              "slots+stash_comparisons",
                              "comparisons+bit_accesses",
                              "key_comparisons"};

static void verify_all(
    const uint64_t *c, size_t n, const uint64_t *s, size_t m, const unsigned char *truth) {
    unsigned char *hits = allocate(n, 1);
    for (size_t method = 0; method < METHOD_COUNT; method++) {
        memset(hits, 0, n);
        measurement r = methods[method](c, n, s, m, hits);
        require(!r.rejected, "unique test accepted");
        require(memcmp(hits, truth, n) == 0, names[method]);
        if (method == NESTED_LOOP) {
            size_t matches = 0;
            for (size_t i = 0; i < n; i++)
                matches += truth[i];
            if (matches == 0)
                require(r.probe_work == (uint64_t)n * m, "disjoint comparison count");
        }
        if (method == HASH_PROBE)
            require(r.hash_calls == n + m, "hash call count");
        if (method == BA_TAG)
            require(r.hash_calls == 2 * n + m, "BA model hash call count");
        if (method == BLOOM_PREFILTER)
            require(r.hash_calls == 2 * (n + m), "Bloom hash call count");
    }
    free(hits);
}

static void self_test(void) {
    uint64_t c[64], s[64];
    unsigned char truth[64];
    size_t cases = 0;
    /* Empty, unequal, zero/full/partial overlap, with known per-position truth. */
    for (size_t n = 0; n <= 32; n += 4) {
        for (size_t m = 0; m <= 32; m += 4) {
            size_t limit = n < m ? n : m;
            for (size_t k = 0; k <= limit; k++) {
                generate(c, n, s, m, k, UINT64_MAX - cases, truth);
                verify_all(c, n, s, m, truth);
                cases++;
            }
        }
    }
    uint64_t edges_c[] = {0, UINT64_MAX, 9, 8};
    uint64_t edges_s[] = {UINT64_MAX, 0, 9};
    unsigned char edges_truth[] = {1, 1, 1, 0};
    verify_all(edges_c, 4, edges_s, 3, edges_truth);
    /* Force a long probe cluster, including one absent colliding key. */
    size_t found = 0;
    for (uint64_t key = 0; found < 17; key++) {
        if ((mix(key) & 31) == 0)
            c[found++] = key;
    }
    memcpy(s, c, 16 * sizeof *s);
    memset(truth, 1, 16);
    truth[16] = 0;
    verify_all(c, 17, s, 16, truth);

    /* All four server keys map to the same pair of cuckoo cells. */
    found = 0;
    for (uint64_t key = 0; found < 5; key++) {
        if (cuckoo_slot(key, 8, 0) == 0 && cuckoo_slot(key, 8, 1) == 8)
            c[found++] = key;
    }
    memcpy(s, c, 4 * sizeof *s);
    memset(truth, 1, 4);
    truth[4] = 0;
    verify_all(c, 5, s, 4, truth);
    unsigned char hits[64] = {0};
    measurement r = cuckoo_probe(c, 5, s, 4, hits);
    require(r.stash_size >= 2 && r.stash_probes > 0, "cuckoo stash exercised");

    memset(hits, 0, sizeof hits);
    r = bloom_run(c, 5, s, 4, hits, 1);
    require(r.filter_passes == 5 && r.false_positives == 1, "Bloom false positive exercised");
    require(memcmp(hits, truth, 5) == 0, "Bloom false positive rejected exactly");

    uint64_t duplicate_c[] = {9, 9, 8}, duplicate_s[] = {9, 9};
    unsigned char duplicate_truth[] = {1, 1, 0};
    for (size_t method = 0; method < METHOD_COUNT; method++) {
        memset(hits, 0, sizeof hits);
        r = methods[method](duplicate_c, 3, duplicate_s, 2, hits);
        if (method == BA_TAG)
            require(r.rejected, "duplicate client labels rejected");
        else
            require(memcmp(hits, duplicate_truth, 3) == 0, "baseline duplicate membership");
    }
    memset(hits, 0, sizeof hits);
    r = ba_tag_match(duplicate_c, 1, duplicate_s, 2, hits);
    require(r.rejected, "ambiguous server match rejected");
    memset(hits, 0, sizeof hits);
    r = ba_tag_match(duplicate_c + 2, 1, duplicate_s, 2, hits);
    require(!r.rejected && !hits[0], "unmatched duplicate server label retained");
    fprintf(
        stderr,
        "PASS: %zu unique input cases x %d methods; forced cuckoo stash, Bloom false positive, duplicate membership and BA model rejection checks.\n",
        cases + 3,
        METHOD_COUNT);
}

static uint64_t parse(const char *text) {
    require(text && *text >= '0' && *text <= '9', "unsigned integer required");
    errno = 0;
    char *end;
    unsigned long long value = strtoull(text, &end, 10);
    require(errno == 0 && *end == '\0' && value <= UINT64_MAX, "invalid integer");
    return (uint64_t)value;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        self_test();
        return 0;
    }
    int with_naive = argc > 1 && strcmp(argv[argc - 1], "--with-naive") == 0;
    if (with_naive)
        argc--;
    if (argc < 4 || argc > 6) {
        fprintf(stderr,
                "Usage: %s N M K [REPEATS=5 [SEED=20260929]] [--with-naive]\n"
                "       %s --self-test\n"
                "Five paper strategies by default; optional sixth quadratic reference.\n"
                "BA-APSI is a precomputed-label matching model, not cryptographic Intersect.\n"
                "CSV is written to stdout; no warmup, no cryptography.\n",
                argv[0],
                argv[0]);
        return argc == 2 && strcmp(argv[1], "--help") == 0 ? 0 : 2;
    }
    uint64_t n64 = parse(argv[1]), m64 = parse(argv[2]), k64 = parse(argv[3]);
    uint64_t repeats = argc > 4 ? parse(argv[4]) : 5;
    uint64_t seed = argc > 5 ? parse(argv[5]) : 20260929;
    require(n64 <= 10000000 && m64 <= 10000000 && k64 <= n64 && k64 <= m64,
            "require 0 <= K <= min(N,M), N,M <= 10000000");
    require(repeats >= 1 && repeats <= 1000, "require 1 <= REPEATS <= 1000");
    size_t n = (size_t)n64, m = (size_t)m64, k = (size_t)k64;
    uint64_t *c = allocate(n, sizeof *c), *s = allocate(m, sizeof *s);
    unsigned char *truth = allocate(n, 1), *hits = allocate(n, 1);
    puts(
        "method,n,m,k,rep,seed,build_ms,probe_ms,total_ms,work_unit,build_work,probe_work,total_work,hash_calls,stash_size,stash_probes,filter_passes,false_positives,index_checks,rejected,matches,validation");
    size_t method_count = with_naive ? METHOD_COUNT : METHOD_COUNT - 1;
    for (uint64_t rep = 0; rep < repeats; rep++) {
        generate(c, n, s, m, k, seed + rep, truth);
        /* Rotate order; all methods receive identical, unchanged inputs. */
        for (size_t step = 0; step < method_count; step++) {
            size_t method = (size_t)((rep + step) % method_count);
            memset(hits, 0, n);
            measurement r = methods[method](c, n, s, m, hits);
            require(!r.rejected, "generated unique labels accepted");
            require(memcmp(hits, truth, n) == 0, "exact per-position oracle");
            size_t matches = 0;
            for (size_t i = 0; i < n; i++)
                matches += hits[i];
            require(matches == k, "intersection size oracle");
            printf("%s,%zu,%zu,%zu,%" PRIu64 ",%" PRIu64 ",%.6f,%.6f,%.6f,%s,%" PRIu64 ",%" PRIu64
                   ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
                   ",%" PRIu64 ",%d,%zu,PASS\n",
                   names[method],
                   n,
                   m,
                   k,
                   rep,
                   seed + rep,
                   r.build_ms,
                   r.probe_ms,
                   r.build_ms + r.probe_ms,
                   units[method],
                   r.build_work,
                   r.probe_work,
                   r.build_work + r.probe_work,
                   r.hash_calls,
                   r.stash_size,
                   r.stash_probes,
                   r.filter_passes,
                   r.false_positives,
                   r.index_checks,
                   r.rejected,
                   matches);
        }
    }
    free(hits);
    free(truth);
    free(s);
    free(c);
    require(fflush(stdout) == 0 && !ferror(stdout), "CSV write failed");
    return 0;
}
