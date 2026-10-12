#define _POSIX_C_SOURCE 200809L

#include "ba.h"

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

const char *ba_status_name(ba_status s) {
    const char *v[] = {"OK", "INVALID", "DUPLICATE", "NO_SOLUTION", "RESOURCE_LIMIT"};
    return (unsigned)s < sizeof(v) / sizeof(v[0]) ? v[s] : "UNKNOWN";
}

void ba_require(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "Operational failure: %s\n", what);
        exit(2);
    }
}

void *ba_alloc(size_t n, size_t width) {
    ba_require(width && n <= SIZE_MAX / width, "allocation size overflow");
    void *v = calloc(n ? n : 1, width);
    ba_require(v != NULL, "out of memory");
    return v;
}

void ba_u64be(unsigned char out[8], uint64_t x) {
    for (unsigned i = 0; i < 8; i++)
        out[7 - i] = (unsigned char)(x >> (8 * i));
}

uint64_t ba_random_below(uint64_t n) {
    ba_require(n != 0, "empty random interval");
    uint64_t x, lim = (uint64_t)(-n) % n;
    do {
        ba_require(RAND_bytes((unsigned char *)&x, sizeof x) == 1, "RAND_bytes");
    } while (x < lim);
    return x % n;
}

static void pbc_rng(mpz_t z, mpz_t limit, void *unused) {
    (void)unused;
    ba_require(mpz_sgn(limit) > 0, "PBC random range");

    size_t bits = mpz_sizeinbase(limit, 2), n = (bits + 7) / 8;
    ba_require(n <= INT_MAX, "PBC random length");
    unsigned char *buf = ba_alloc(n, 1);
    do {
        ba_require(RAND_bytes(buf, (int)n) == 1, "PBC random source");
        if (bits % 8)
            buf[0] &= (unsigned char)((1u << (bits % 8)) - 1u);
        mpz_import(z, n, 1, 1, 0, 0, buf);
    } while (mpz_cmp(z, limit) >= 0);

    OPENSSL_cleanse(buf, n);
    free(buf);
}

void ba_random_init(void) {
    pbc_random_set_function(pbc_rng, NULL);
}

double ba_now_ms(void) {
    struct timespec t;
    ba_require(clock_gettime(CLOCK_MONOTONIC, &t) == 0, "clock_gettime");
    return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1000000.0;
}

void ba_digest(
    const char *domain, const void *a, size_t an, const void *b, size_t bn, unsigned char out[32]) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned char len[8];
    unsigned n;
    ba_require(c != NULL, "digest context");
    ba_require(EVP_DigestInit_ex(c, EVP_sha256(), NULL) == 1, "digest init");

    ba_u64be(len, strlen(domain));
    ba_require(EVP_DigestUpdate(c, len, 8) == 1, "digest");
    ba_require(EVP_DigestUpdate(c, domain, strlen(domain)) == 1, "digest");

    ba_u64be(len, an);
    ba_require(EVP_DigestUpdate(c, len, 8) == 1, "digest");
    if (an)
        ba_require(EVP_DigestUpdate(c, a, an) == 1, "digest");

    ba_u64be(len, bn);
    ba_require(EVP_DigestUpdate(c, len, 8) == 1, "digest");
    if (bn)
        ba_require(EVP_DigestUpdate(c, b, bn) == 1, "digest");

    ba_require(EVP_DigestFinal_ex(c, out, &n) == 1 && n == 32, "digest final");
    EVP_MD_CTX_free(c);
}

static uint64_t hash_key(const unsigned char *p, size_t n) {
    uint64_t h = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < n; i++)
        h = (h ^ p[i]) * UINT64_C(1099511628211);
    h ^= h >> 33;
    h *= UINT64_C(0xff51afd7ed558ccd);
    h ^= h >> 33;
    return h;
}

ba_status ba_table_init(ba_table *t, size_t entries, size_t keylen, size_t maxbytes) {
    memset(t, 0, sizeof *t);
    size_t cap = 2;
    if (!keylen || entries > SIZE_MAX / 2)
        return BA_RESOURCE;

    while (cap < entries * 2) {
        if (cap > SIZE_MAX / 2)
            return BA_RESOURCE;
        cap *= 2;
    }

    if (keylen > SIZE_MAX - sizeof(uint64_t) - sizeof(size_t))
        return BA_RESOURCE;
    size_t width = keylen + sizeof(uint64_t) + sizeof(size_t);
    if (cap > SIZE_MAX / width || cap * width > maxbytes)
        return BA_RESOURCE;

    t->keys = ba_alloc(cap, keylen);
    t->val = ba_alloc(cap, sizeof(uint64_t));
    t->count = ba_alloc(cap, sizeof(size_t));
    t->cap = cap;
    t->keylen = keylen;
    t->bytes = cap * width;
    return BA_OK;
}

void ba_table_clear(ba_table *t) {
    free(t->keys);
    free(t->val);
    free(t->count);
    memset(t, 0, sizeof *t);
}

size_t ba_table_find(const ba_table *t, const unsigned char *key) {
    size_t slot = (size_t)hash_key(key, t->keylen) & (t->cap - 1);
    while (t->count[slot] && memcmp(key, t->keys + slot * t->keylen, t->keylen))
        slot = (slot + 1) & (t->cap - 1);
    return slot;
}

void ba_table_insert(ba_table *t, const unsigned char *key, uint64_t value) {
    size_t i = ba_table_find(t, key);
    if (t->count[i]) {
        t->count[i]++;
        return;
    }

    ba_require(t->len < t->cap / 2, "table capacity");
    memcpy(t->keys + i * t->keylen, key, t->keylen);
    t->val[i] = value;
    t->count[i] = 1;
    t->len++;
}
