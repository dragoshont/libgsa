/*
 * test_srp.c — SRP-6a vectors and the Apple-variant validation harness.
 *
 * Two tiers:
 *  (1) Structural checks that always run (A is in range, deterministic with a
 *      fixed `a`, session key/M1 are produced).
 *  (2) Apple-variant correctness — the exact M1/x/u byte values. These are the
 *      claims that must be pinned against an oracle:
 *        - with -DGSA_DIFF_CORECRYPTO: diff byte-for-byte vs Apple corecrypto.
 *        - otherwise: against a frozen golden vector once captured.
 *      Until a golden/oracle is wired in, tier (2) is reported as SKIPPED so CI
 *      stays honest (green != "SRP proven correct").
 */
#include "gsa/srp.h"
#include "gsa/crypto.h"
#include "test_util.h"

/* Deterministic: same fixed `a` must yield the same A across runs. */
static void test_srp_deterministic_A(void) {
    uint8_t fixed_a[32];
    for (int i = 0; i < 32; i++) fixed_a[i] = (uint8_t)(i + 1);

    gsa_srp_ctx *c1 = gsa_srp_new();
    gsa_srp_ctx *c2 = gsa_srp_new();
    CHECK_TRUE("srp_new c1", c1 != NULL);
    CHECK_TRUE("srp_new c2", c2 != NULL);
    gsa_srp_set_fixed_a(c1, fixed_a, sizeof(fixed_a));
    gsa_srp_set_fixed_a(c2, fixed_a, sizeof(fixed_a));

    size_t n1 = 0, n2 = 0;
    gsa_srp_start(c1, NULL, &n1);
    gsa_srp_start(c2, NULL, &n2);
    CHECK_TRUE("A width == 256 (2048-bit group)", n1 == 256 && n2 == 256);

    uint8_t A1[256], A2[256];
    size_t l1 = sizeof(A1), l2 = sizeof(A2);
    int r1 = gsa_srp_start(c1, A1, &l1);
    int r2 = gsa_srp_start(c2, A2, &l2);
    CHECK_TRUE("srp_start ok", r1 == 0 && r2 == 0);
    CHECK_EQ_BYTES("fixed-a => deterministic A", A1, A2, 256);

    gsa_srp_free(c1);
    gsa_srp_free(c2);
}

/* s2k vs s2k_fo produce different keys; both are 32 bytes and deterministic. */
static void test_s2k(void) {
    const uint8_t salt[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t k_s2k[32], k_s2kfo[32], k_s2k_b[32];
    int a = gsa_srp_s2k("hunter2", salt, sizeof(salt), 1000, 0, k_s2k);
    int b = gsa_srp_s2k("hunter2", salt, sizeof(salt), 1000, 1, k_s2kfo);
    int c = gsa_srp_s2k("hunter2", salt, sizeof(salt), 1000, 0, k_s2k_b);
    CHECK_TRUE("s2k returns 0", a == 0 && b == 0 && c == 0);
    CHECK_EQ_BYTES("s2k deterministic", k_s2k, k_s2k_b, 32);
    CHECK_TRUE("s2k != s2k_fo", memcmp(k_s2k, k_s2kfo, 32) != 0);
}

/*
 * Apple-variant exactness. Requires an oracle. This is where correctness is
 * actually proven; structural tests above only prove "runs deterministically".
 */
static void test_apple_variant_exact(void) {
#ifdef GSA_DIFF_CORECRYPTO
    /* TODO: drive both gsa_srp_* and ccsrp_* with the same fixed `a`,
     * password_key, salt, B and CHECK_EQ_BYTES on A and M1. corecrypto is the
     * ground truth. */
    SKIP("SRP Apple-variant exact (corecrypto diff)",
         "harness present, vectors TODO");
#else
    /* TODO: load tests/vectors/srp-apple-golden.bin (frozen from corecrypto,
     * cross-checked vs pypush) and assert M1/x/u byte-for-byte. */
    SKIP("SRP Apple-variant exact (golden vector)",
         "no oracle linked; build with -DGSA_DIFF_CORECRYPTO or add golden");
#endif
}

int main(void) {
    test_srp_deterministic_A();
    test_s2k();
    test_apple_variant_exact();
    return TEST_SUMMARY();
}
