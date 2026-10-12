#include "ba_baselines.h"

#include <stdlib.h>
#include <string.h>

static int cmp(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint64_t mix(uint64_t x) {
    x ^= x >> 30;
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}

static size_t pos(uint64_t x, size_t cap, unsigned which) {
    return (size_t)mix(x ^ (which ? UINT64_C(0x9e3779b97f4a7c15) : UINT64_C(0x243f6a8885a308d3))) &
           (cap - 1);
}

ba_status ba_baseline_run(ba_baseline method,
                          const uint64_t *c,
                          size_t n,
                          const uint64_t *s,
                          size_t m,
                          unsigned char *hits,
                          ba_baseline_stats *st) {
    memset(st, 0, sizeof *st);
    memset(hits, 0, n);
    if (m > SIZE_MAX / 32 || (unsigned)method > BASE_BLOOM)
        return BA_INVALID;
    double start = ba_now_ms();
    if (method == BASE_HASH) {
        ba_table t;
        ba_status status = ba_table_init(&t, m, 8, SIZE_MAX);
        if (status != BA_OK)
            return status;
        for (size_t j = 0; j < m; j++) {
            unsigned char key[8];
            ba_u64be(key, s[j]);
            ba_table_insert(&t, key, j);
        }
        st->table_bytes = t.bytes;
        st->build_ms = ba_now_ms() - start;
        start = ba_now_ms();
        for (size_t i = 0; i < n; i++) {
            unsigned char key[8];
            ba_u64be(key, c[i]);
            hits[i] = (unsigned char)(t.count[ba_table_find(&t, key)] != 0);
        }
        st->probe_ms = ba_now_ms() - start;
        ba_table_clear(&t);
        return BA_OK;
    }
    if (method == BASE_CUCKOO) {
        size_t cap = 2;
        while (cap < m * 2)
            cap *= 2;
        uint64_t *table = ba_alloc(cap * 2, sizeof(uint64_t)),
                 *stash = ba_alloc(m, sizeof(uint64_t));
        unsigned char *used = ba_alloc(cap * 2, 1);
        size_t count = 0;
        for (size_t j = 0; j < m; j++) {
            uint64_t key = s[j];
            unsigned side = 0;
            int inserted = 0;
            for (unsigned kick = 0; kick < 512; kick++) {
                size_t i = side * cap + pos(key, cap, side);
                if (!used[i]) {
                    used[i] = 1;
                    table[i] = key;
                    inserted = 1;
                    break;
                }
                uint64_t old = table[i];
                table[i] = key;
                key = old;
                side ^= 1;
            }
            if (!inserted)
                stash[count++] = key;
        }
        st->table_bytes = cap * 2 * (sizeof(uint64_t) + 1) + m * sizeof(uint64_t);
        st->stash_size = count;
        st->build_ms = ba_now_ms() - start;
        start = ba_now_ms();
        for (size_t i = 0; i < n; i++) {
            size_t a = pos(c[i], cap, 0), b = cap + pos(c[i], cap, 1);
            int found = (used[a] && table[a] == c[i]) || (used[b] && table[b] == c[i]);
            for (size_t j = 0; j < count && !found; j++)
                found = stash[j] == c[i];
            hits[i] = (unsigned char)found;
        }
        st->probe_ms = ba_now_ms() - start;
        free(table);
        free(stash);
        free(used);
        return BA_OK;
    }
    uint64_t *sorted = ba_alloc(m, sizeof(uint64_t));
    if (m)
        memcpy(sorted, s, m * sizeof(uint64_t));
    qsort(sorted, m, sizeof(uint64_t), cmp);
    if (method == BASE_SORT) {
        /* Sort client (ID, original position), then a linear merge. */
        typedef struct {
            uint64_t id;
            size_t index;
        } item;

        /* A separate client sort by ID uses two uint64 words to keep comparator simple. */
        item *client = ba_alloc(n, sizeof(item));
        for (size_t i = 0; i < n; i++) {
            client[i].id = c[i];
            client[i].index = i;
        }
        qsort(client, n, sizeof(item), cmp);
        st->table_bytes = m * 8 + n * sizeof(item);
        st->build_ms = ba_now_ms() - start;
        start = ba_now_ms();
        size_t i = 0, j = 0;
        while (i < n && j < m) {
            if (client[i].id == sorted[j]) {
                hits[client[i].index] = 1;
                i++;
            } else if (client[i].id < sorted[j])
                i++;
            else
                j++;
        }
        st->probe_ms = ba_now_ms() - start;
        free(client);
        free(sorted);
        return BA_OK;
    }
    size_t bits = m ? m * 12 : 64, bytes = (bits + 7) / 8;
    unsigned char *bloom = ba_alloc(bytes, 1);
    for (size_t j = 0; j < m; j++) {
        uint64_t a = mix(s[j]), b = mix(s[j] ^ UINT64_C(0xa0761d6478bd642f)) | 1;
        for (unsigned h = 0; h < 8; h++) {
            size_t at = (size_t)((a + h * b) % bits);
            bloom[at / 8] |= (unsigned char)(1u << (at % 8));
        }
    }
    st->table_bytes = m * 8 + bytes;
    st->build_ms = ba_now_ms() - start;
    start = ba_now_ms();
    for (size_t i = 0; i < n; i++) {
        uint64_t a = mix(c[i]), b = mix(c[i] ^ UINT64_C(0xa0761d6478bd642f)) | 1;
        int possible = 1;
        for (unsigned h = 0; h < 8; h++) {
            size_t at = (size_t)((a + h * b) % bits);
            if (!(bloom[at / 8] & (1u << (at % 8)))) {
                possible = 0;
                break;
            }
        }
        if (possible) {
            st->filter_passes++;
            hits[i] = (unsigned char)(bsearch(&c[i], sorted, m, sizeof(uint64_t), cmp) != NULL);
        }
    }
    st->probe_ms = ba_now_ms() - start;
    free(bloom);
    free(sorted);
    return BA_OK;
}
