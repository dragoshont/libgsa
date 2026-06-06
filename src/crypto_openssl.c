/*
 * crypto_openssl.c — gsa/crypto.h implemented on OpenSSL.
 *
 * Every function is a deterministic standard primitive (SHA-256, HMAC, PBKDF2,
 * AES-256-CBC/PKCS7, AES-256-GCM). No Apple code. Covered by RFC/NIST vectors
 * in tests/test_primitives.c.
 */
#include "gsa/crypto.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

void gsa_sha256(const uint8_t *data, size_t len, uint8_t out[GSA_SHA256_LEN]) {
    unsigned int outlen = GSA_SHA256_LEN;
    EVP_Digest(data, len, out, &outlen, EVP_sha256(), NULL);
}

void gsa_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[GSA_SHA256_LEN]) {
    unsigned int outlen = GSA_SHA256_LEN;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &outlen);
}

int gsa_pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                           const uint8_t *salt, size_t salt_len,
                           uint32_t iterations,
                           uint8_t *out, size_t out_len) {
    /* PKCS5_PBKDF2_HMAC returns 1 on success. */
    int ok = PKCS5_PBKDF2_HMAC((const char *)password, (int)password_len,
                               salt, (int)salt_len, (int)iterations,
                               EVP_sha256(), (int)out_len, out);
    return ok == 1 ? 0 : -1;
}

int gsa_aes256_cbc_pkcs7_decrypt(const uint8_t key[32], const uint8_t iv[16],
                                 const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int rc = -1;
    int len = 0, total = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        goto done;
    /* PKCS#7 padding is on by default for CBC in OpenSSL. */
    if (EVP_DecryptUpdate(ctx, out, &len, in, (int)in_len) != 1)
        goto done;
    total = len;
    if (EVP_DecryptFinal_ex(ctx, out + total, &len) != 1)
        goto done; /* bad padding / wrong key */
    total += len;

    *out_len = (size_t)total;
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int gsa_aes256_gcm_decrypt(const uint8_t key[32],
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *in, size_t in_len,
                           const uint8_t tag[16],
                           uint8_t *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int rc = -1;
    int len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1)
        goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto done;
    if (aad && aad_len) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
            goto done;
    }
    if (in_len) {
        if (EVP_DecryptUpdate(ctx, out, &len, in, (int)in_len) != 1)
            goto done;
    }
    /* Set the expected tag, then finalize to verify it. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1)
        goto done;
    if (EVP_DecryptFinal_ex(ctx, out + len, &len) != 1)
        goto done; /* tag mismatch */

    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int gsa_consttime_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    return CRYPTO_memcmp(a, b, len) == 0 ? 1 : 0;
}

int gsa_random_bytes(uint8_t *out, size_t len) {
    return RAND_bytes(out, (int)len) == 1 ? 0 : -1;
}
