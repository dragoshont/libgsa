/*
 * gsa/crypto.h — corecrypto-free crypto primitives for GrandSlam auth.
 *
 * Thin, deterministic wrappers over OpenSSL that match exactly the primitives
 * AltSign's AppleAPI+Authentication.cpp pulls from the corecrypto headers:
 *   ccsha256_di      -> gsa_sha256
 *   cchmac           -> gsa_hmac_sha256
 *   ccpbkdf2_hmac    -> gsa_pbkdf2_hmac_sha256
 *   ccaes_cbc + ccpad_pkcs7_decrypt -> gsa_aes256_cbc_pkcs7_decrypt
 *   ccaes_gcm        -> gsa_aes256_gcm_decrypt
 *   cc_cmp_safe      -> gsa_consttime_eq
 *
 * All functions are pure / byte-deterministic and covered by RFC/NIST vectors.
 * No Apple code is involved.
 */
#ifndef GSA_CRYPTO_H
#define GSA_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GSA_SHA256_LEN 32

/* SHA-256 of `len` bytes at `data` into `out[32]`. */
void gsa_sha256(const uint8_t *data, size_t len, uint8_t out[GSA_SHA256_LEN]);

/* HMAC-SHA256(key, data) into `out[32]`. */
void gsa_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[GSA_SHA256_LEN]);

/*
 * PBKDF2-HMAC-SHA256. Returns 0 on success, non-zero on failure.
 * (RFC 6070-equivalent for SHA-256.)
 */
int gsa_pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                           const uint8_t *salt, size_t salt_len,
                           uint32_t iterations,
                           uint8_t *out, size_t out_len);

/*
 * AES-256-CBC decrypt with PKCS#7 unpadding.
 * `key` must be 32 bytes, `iv` 16 bytes. `out` must hold at least `in_len`
 * bytes; the actual plaintext length is written to *out_len.
 * Returns 0 on success, non-zero on failure (incl. bad padding).
 */
int gsa_aes256_cbc_pkcs7_decrypt(const uint8_t key[32], const uint8_t iv[16],
                                 const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t *out_len);

/*
 * AES-256-GCM decrypt + verify. `key` 32 bytes, `iv` `iv_len` bytes,
 * `aad` optional additional-authenticated-data, `tag` 16 bytes.
 * Returns 0 if the tag verifies and plaintext is written to `out`
 * (`in_len` bytes), non-zero on auth failure.
 */
int gsa_aes256_gcm_decrypt(const uint8_t key[32],
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *in, size_t in_len,
                           const uint8_t tag[16],
                           uint8_t *out);

/* Constant-time equality. Returns 1 if equal, 0 otherwise. */
int gsa_consttime_eq(const uint8_t *a, const uint8_t *b, size_t len);

/* Cryptographically secure random bytes. Returns 0 on success. */
int gsa_random_bytes(uint8_t *out, size_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GSA_CRYPTO_H */
