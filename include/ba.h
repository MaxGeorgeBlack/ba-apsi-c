#ifndef BA_H
#define BA_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <pbc/pbc.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#define BA_POINT_BYTES 33
#define BA_CT_BYTES 66
#define BA_CONTEXT_BYTES 32

typedef enum { BA_OK = 0, BA_INVALID, BA_DUPLICATE, BA_NO_SOLUTION, BA_RESOURCE } ba_status;

const char *ba_status_name(ba_status s);
void ba_require(int ok, const char *what);
void *ba_alloc(size_t n, size_t width);
uint64_t ba_random_below(uint64_t n);
void ba_random_init(void);
double ba_now_ms(void);
void ba_u64be(unsigned char out[8], uint64_t x);
void ba_digest(
    const char *domain, const void *a, size_t an, const void *b, size_t bn, unsigned char out[32]);

/* Full-key dictionary, with multiplicities retained. */
typedef struct {
    size_t cap, len, keylen, bytes;
    unsigned char *keys;
    uint64_t *val;
    size_t *count;
} ba_table;

ba_status ba_table_init(ba_table *t, size_t entries, size_t keylen, size_t maxbytes);
void ba_table_clear(ba_table *t);
size_t ba_table_find(const ba_table *t, const unsigned char *key);
void ba_table_insert(ba_table *t, const unsigned char *key, uint64_t value);

typedef struct {
    EC_GROUP *group;
    BN_CTX *ctx;
    BIGNUM *order;
} ba_ec;

void ba_ec_init(ba_ec *e);
void ba_ec_clear(ba_ec *e);
BIGNUM *ba_bn_u64(uint64_t n);
void ba_ec_mul_i64(ba_ec *e, EC_POINT *out, int64_t n);
void ba_ec_encode(ba_ec *e, const EC_POINT *p, unsigned char out[BA_POINT_BYTES]);
ba_status ba_ec_decode(ba_ec *e, EC_POINT *p, const unsigned char in[BA_POINT_BYTES]);

typedef struct {
    unsigned char bytes[BA_CT_BYTES];
} ba_ciphertext;

void ba_encrypt(ba_ec *e, const EC_POINT *pk, uint64_t v, ba_ciphertext *out);
/* Explicit coins ONLY for boundary tests, never used by the benchmark. */
void ba_encrypt_with_coin(
    ba_ec *e, const EC_POINT *pk, uint64_t v, const BIGNUM *r, ba_ciphertext *out);
ba_status ba_decrypt_point(ba_ec *e, const BIGNUM *sk, const ba_ciphertext *ct, EC_POINT *out);

typedef enum { BA_BSGS = 0, BA_KANGAROO = 1 } ba_solver;

typedef enum { BA_DLP_FULL_BUDGET = 0, BA_DLP_EARLY_STOP = 1 } ba_dlp_strategy;

typedef struct {
    ba_solver solver;
    size_t max_table_bytes;
    uint64_t tame, wild;
    unsigned attempts;
    ba_dlp_strategy strategy; /* Early stop is supported by prepared recovery only. */
} ba_dlp_options;

typedef struct {
    uint64_t baby_steps, giant_steps, tame_steps, wild_steps;
    size_t peak_table_bytes;
    unsigned attempts;
    int fallback;
} ba_dlp_stats;

ba_dlp_options ba_dlp_defaults(ba_solver solver);
ba_status ba_dlp(ba_ec *e,
                 const EC_POINT *v,
                 int64_t a,
                 int64_t b,
                 const ba_dlp_options *opt,
                 int64_t *answer,
                 ba_dlp_stats *stats);
uint64_t ba_ceil_sqrt(uint64_t n);

/* Public, target-independent DLP preprocessing. Owned by the caller and tied
 * to this ba_ec instance/group; clear before ba_ec_clear. Tables and public
 * walk seeds remain immutable across targets. The table cap is cumulative.
 * FULL_BUDGET retains the original budgets. EARLY_STOP verifies the first hit
 * and returns; Kangaroo uses a lower-end tame anchor and denser public jumps.
 * Both strategies retain verified, complete BSGS fallback. Neither is oblivious. */
typedef struct ba_dlp_prepared ba_dlp_prepared;
ba_status ba_dlp_prepare(ba_ec *e,
                         int64_t a,
                         int64_t b,
                         const ba_dlp_options *opt,
                         ba_dlp_prepared **out,
                         ba_dlp_stats *offline_stats);
void ba_dlp_prepared_clear(ba_dlp_prepared *prepared);
int ba_dlp_prepared_matches(const ba_dlp_prepared *prepared, const ba_ec *e, int64_t a, int64_t b);
void ba_dlp_prepared_id(const ba_dlp_prepared *prepared, unsigned char out[32]);
ba_status ba_dlp_execute(ba_ec *e,
                         const EC_POINT *v,
                         const ba_dlp_prepared *prepared,
                         int64_t *answer,
                         ba_dlp_stats *online_stats);

/* Owned PBC objects must belong to this pairing. No network wire API. */
typedef struct {
    size_t universe, nc, ns, degree;
    uint64_t max_value, bound;
} ba_config;

typedef struct {
    pairing_t pairing;
    element_t g, Y;
    element_t *T;
    ba_ec ec;
    EC_POINT *pk;
    ba_config cfg;
    unsigned char period[32];
    int active;
} ba_public;

typedef struct {
    element_t *coeff, *t;
    size_t degree, universe;
} ba_authority;

typedef struct {
    BIGNUM *sk;
} ba_recoverer;

typedef struct {
    size_t n;
    uint64_t *ids;
    element_t *sigma;
    unsigned char period[32];
} ba_certificates;

typedef int (*ba_policy)(uint64_t id, void *arg);

typedef struct {
    element_t x, rc;
    unsigned char context[32];
    int active;
} ba_request;

typedef struct {
    element_t rs;
    element_t *P;
    size_t *source;
    size_t n;
    unsigned char context[32];
    int active;
} ba_response;

typedef struct {
    size_t client_index, response_index;
    unsigned char *token;
} ba_match;

typedef struct {
    ba_match *items;
    size_t n, token_bytes;
    unsigned char context[32];
} ba_matches;

typedef struct {
    size_t index;
    ba_ciphertext masked;
} ba_packet;

typedef struct {
    size_t n;
    ba_packet *items;
    unsigned char context[32];
} ba_payloads;

ba_status ba_setup(
    ba_public *p, ba_authority *a, ba_recoverer *r, const char *params, const ba_config *cfg);
void ba_setup_clear(ba_public *p, ba_authority *a, ba_recoverer *r);
ba_status ba_authorize(ba_public *p,
                       ba_authority *a,
                       const uint64_t *ids,
                       size_t n,
                       ba_policy policy,
                       void *arg,
                       ba_certificates *out);
void ba_certificates_clear(ba_certificates *s);
void ba_context(ba_public *p,
                const char *client,
                const char *server,
                const unsigned char session[32],
                unsigned char out[32]);
void ba_client_begin(ba_public *p, const unsigned char ctx[32], ba_request *r);
void ba_request_clear(ba_request *r);
ba_status ba_server_respond(ba_public *p,
                            ba_certificates *s,
                            ba_request *r,
                            const unsigned char ctx[32],
                            int optimized,
                            ba_response *out);
void ba_response_clear(ba_response *r);
ba_status ba_client_match(ba_public *p,
                          ba_certificates *c,
                          ba_request *r,
                          ba_response *s,
                          int optimized,
                          ba_matches *out);
void ba_matches_clear(ba_matches *m);
ba_status ba_encapsulate(
    ba_public *p, ba_certificates *c, const uint64_t *values, ba_matches *m, ba_payloads *out);
void ba_payloads_clear(ba_payloads *c);
ba_status ba_blind_aggregate(ba_public *p, ba_response *s, ba_payloads *c, ba_ciphertext *out);
ba_status ba_recover(ba_public *p,
                     ba_recoverer *r,
                     const ba_ciphertext *ct,
                     const ba_dlp_options *opt,
                     uint64_t *answer,
                     ba_dlp_stats *stats);
ba_status ba_recover_prepared(ba_public *p,
                              ba_recoverer *r,
                              const ba_ciphertext *ct,
                              const ba_dlp_prepared *prepared,
                              uint64_t *answer,
                              ba_dlp_stats *stats);

#endif
