/* Independent direct-power oracle for the fixed-base optimization. */
#include "ba.h"

#include <stdio.h>
#include <stdlib.h>

static int approve(uint64_t id, void *p) {
    (void)id;
    (void)p;
    return 1;
}

static void check(int ok) {
    if (!ok) {
        fputs("Fixed-base algebra check FAILED\n", stderr);
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    ba_random_init();
    ba_config cfg = {64, 64, 64, 4, 10, 0};
    ba_public p;
    ba_authority a;
    ba_recoverer r;
    check(ba_setup(&p, &a, &r, argv[1], &cfg) == BA_OK);
    uint64_t ids[64];
    for (size_t i = 0; i < 64; i++)
        ids[i] = i + 1;
    ba_certificates cert;
    check(ba_authorize(&p, &a, ids, 64, approve, NULL, &cert) == BA_OK);
    element_t direct, x, power, sum, term, scalar;
    element_init_G1(direct, p.pairing);
    element_init_Zr(x, p.pairing);
    element_init_Zr(power, p.pairing);
    element_init_Zr(sum, p.pairing);
    element_init_Zr(term, p.pairing);
    element_init_Zr(scalar, p.pairing);
    for (size_t i = 0; i < 64; i++) {
        element_pow_zn(direct, p.g, a.t[i]);
        check(element_cmp(direct, p.T[i]) == 0);
        element_set_si(x, (long)(i + 1));
        element_set1(power);
        element_set0(sum);
        /* Explicit coefficient sum, independent of the issuer's Horner loop. */
        for (size_t j = 0; j < a.degree; j++) {
            element_mul(term, a.coeff[j], power);
            element_add(sum, sum, term);
            element_mul(power, power, x);
        }
        element_div(scalar, sum, a.t[i]);
        element_pow_zn(direct, p.g, scalar);
        check(element_cmp(direct, cert.sigma[i]) == 0);
    }
    element_clear(direct);
    element_clear(x);
    element_clear(power);
    element_clear(sum);
    element_clear(term);
    element_clear(scalar);
    ba_certificates_clear(&cert);
    ba_setup_clear(&p, &a, &r);
    puts("PASS 64 direct public-key powers and 64 independent polynomial certificate powers");
    return 0;
}
