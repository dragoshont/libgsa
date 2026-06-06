/*
 * gsa/srp.h — SRP-6a client, Apple GrandSlam variant, on OpenSSL BIGNUM.
 *
 * Mirrors the corecrypto SRP usage in AltSign's AppleAPI+Authentication.cpp:
 *   - RFC 5054 2048-bit group, SHA-256 hash.
 *   - noUsernameInX: x = H(salt || H(":" || password_key))  (username dropped,
 *     but the ":" separator is retained; proven against the `srp` oracle).
 *   - the "password" fed to SRP is the s2k/s2k_fo-derived key, see gsa_srp_s2k.
 *
 * Flow (matches AppleAPI::Authenticate):
 *   1. gsa_srp_new()            -> ctx
 *   2. gsa_srp_start(ctx, A)    -> client public A   (param "A2k")
 *   3. server returns sp(s2k|s2k_fo), salt s, iterations i, B
 *   4. key = gsa_srp_s2k(...)   -> password key from the user password
 *   5. gsa_srp_process(ctx, key, s, B, M1) -> client proof M1  (param "M1")
 *   6. server returns M2
 *   7. gsa_srp_verify(ctx, M2)  -> 0 if the server proof is valid
 *   8. gsa_srp_session_key(ctx) -> K, used to derive the extra-data keys.
 *
 * EXACT M1/u formulas and whether H(I) is folded into M1 are pinned by the
 * golden-vector test against the MIT `srp` oracle (see tests/test_srp.c and
 * tests/oracle/gsa_oracle.py). The constants here are validated by vector.
 */
#ifndef GSA_SRP_H
#define GSA_SRP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gsa_srp_ctx gsa_srp_ctx;

/* Create / destroy an SRP client context (RFC 5054 2048-bit, SHA-256). */
gsa_srp_ctx *gsa_srp_new(void);
void gsa_srp_free(gsa_srp_ctx *ctx);

/*
 * Optionally seed the client ephemeral `a` with fixed bytes (for deterministic
 * tests / differential vectors). If never called, a CSPRNG value is used.
 * `a_len` is typically 32. Returns 0 on success.
 */
int gsa_srp_set_fixed_a(gsa_srp_ctx *ctx, const uint8_t *a, size_t a_len);

/*
 * Compute the client public value A = g^a mod N.
 * Writes `*a_len` bytes to `out` (the modulus size, 256 for 2048-bit).
 * Pass out=NULL to query the required length in *a_len.
 */
int gsa_srp_start(gsa_srp_ctx *ctx, uint8_t *out, size_t *a_len);

/*
 * Apple s2k / s2k_fo password derivation (the ALTPBKDF2SRP helper):
 *   d = SHA256(utf8 password)
 *   if s2k_fo: d = lowercase_hex(d)        (64 bytes), else d stays 32 bytes
 *   key = PBKDF2-HMAC-SHA256(d, salt, iterations, 32)
 * `is_s2k_fo` selects the "s2k_fo" variant. Returns 0 on success; writes 32
 * bytes to `out_key`.
 */
int gsa_srp_s2k(const char *password,
                const uint8_t *salt, size_t salt_len,
                uint32_t iterations,
                int is_s2k_fo,
                uint8_t out_key[32]);

/*
 * Process the server challenge and produce the client proof M1.
 *   username   : Apple ID (used in M1; NOT in x, per noUsernameInX)
 *   password_key: the 32-byte output of gsa_srp_s2k()
 *   salt, B    : from the server response
 *   out_m1     : 32 bytes (SHA-256 sized)
 * Returns 0 on success.
 */
int gsa_srp_process(gsa_srp_ctx *ctx,
                    const char *username,
                    const uint8_t *password_key, size_t password_key_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *B, size_t B_len,
                    uint8_t out_m1[32]);

/* Verify the server proof M2. Returns 0 if valid, non-zero otherwise. */
int gsa_srp_verify(gsa_srp_ctx *ctx, const uint8_t M2[32]);

/*
 * The negotiated session key K = H(S). Writes `*key_len` bytes to `out`
 * (32 for SHA-256). Pass out=NULL to query the length. Valid after
 * gsa_srp_process().
 */
int gsa_srp_session_key(gsa_srp_ctx *ctx, uint8_t *out, size_t *key_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GSA_SRP_H */
