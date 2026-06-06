/*
 * srp_openssl.c — SRP-6a client (Apple GrandSlam variant) on OpenSSL BIGNUM.
 *
 * Group:  RFC 5054 2048-bit (N, g=2).
 * Hash:   SHA-256.
 * Variant flags observed in AltSign's corecrypto usage:
 *   - noUsernameInX: x = H(salt || H(password_key))   (no "I:" prefix in x).
 *   - the "password_key" is the s2k/s2k_fo PBKDF2 output (see gsa_srp_s2k).
 *
 * Standard SRP-6a math:
 *   A  = g^a mod N
 *   u  = H(PAD(A) | PAD(B))
 *   k  = H(N | PAD(g))
 *   x  = H(s | H(p))                          [noUsernameInX]
 *   S  = (B - k*g^x)^(a + u*x) mod N
 *   K  = H(S)
 *   M1 = H( H(N) XOR H(g) | H(I) | s | A | B | K )
 *   M2 = H( A | M1 | K )
 *
 * !!! VALIDATION REQUIRED !!!
 * Whether Apple folds H(I) into M1 when noUsernameInX is set, and the exact
 * PAD width / endianness, are pinned by tests/test_srp.c (RFC 5054 Appendix B
 * vector + byte-for-byte diff vs corecrypto + cross-check vs pypush). Do not
 * trust this file until those tests are green.
 */
#include "gsa/srp.h"
#include "gsa/crypto.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

/* Incremental SHA-256 over EVP (the low-level SHA256_* API is deprecated in
 * OpenSSL 3.0 and trips -Werror). */
typedef struct { EVP_MD_CTX *m; } sha256_stream;
static void sha256_begin(sha256_stream *s) {
    s->m = EVP_MD_CTX_new();
    EVP_DigestInit_ex(s->m, EVP_sha256(), NULL);
}
static void sha256_add(sha256_stream *s, const void *p, size_t n) {
    if (p && n) EVP_DigestUpdate(s->m, p, n);
}
static void sha256_end(sha256_stream *s, uint8_t out[GSA_SHA256_LEN]) {
    unsigned int l = 0;
    EVP_DigestFinal_ex(s->m, out, &l);
    EVP_MD_CTX_free(s->m);
}

/* RFC 5054, Appendix A — 2048-bit group N (hex), generator g = 2. */
static const char *RFC5054_N_2048_HEX =
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

struct gsa_srp_ctx {
    BIGNUM *N;
    BIGNUM *g;
    BIGNUM *a;     /* client ephemeral private */
    BIGNUM *A;     /* client public g^a */
    BIGNUM *K_bn;  /* premaster S (kept until session key derived) */
    uint8_t *fixed_a;
    size_t   fixed_a_len;
    uint8_t  K[GSA_SHA256_LEN];   /* session key = H(S) */
    int      have_K;
    uint8_t  M1[GSA_SHA256_LEN];
    int      have_M1;
};

static size_t bn_bytes(const BIGNUM *bn) { return (size_t)BN_num_bytes(bn); }

/* Left-pad a BIGNUM to `width` bytes. Caller frees *out. Returns 0 on success. */
static int bn_to_padded(const BIGNUM *bn, size_t width, uint8_t **out) {
    uint8_t *buf = calloc(1, width ? width : 1);
    if (!buf) return -1;
    if (BN_bn2binpad(bn, buf, (int)width) < 0) { free(buf); return -1; }
    *out = buf;
    return 0;
}

/* H(a || b) -> 32 bytes. Either part may be NULL/0. */
static void sha256_cat(const uint8_t *a, size_t alen,
                       const uint8_t *b, size_t blen,
                       uint8_t out[GSA_SHA256_LEN]) {
    sha256_stream c;
    sha256_begin(&c);
    sha256_add(&c, a, alen);
    sha256_add(&c, b, blen);
    sha256_end(&c, out);
}

gsa_srp_ctx *gsa_srp_new(void) {
    gsa_srp_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->g = BN_new();
    if (!ctx->g || BN_hex2bn(&ctx->N, RFC5054_N_2048_HEX) == 0) {
        gsa_srp_free(ctx);
        return NULL;
    }
    BN_set_word(ctx->g, 2);
    return ctx;
}

void gsa_srp_free(gsa_srp_ctx *ctx) {
    if (!ctx) return;
    BN_free(ctx->N);
    BN_free(ctx->g);
    BN_clear_free(ctx->a);
    BN_free(ctx->A);
    BN_clear_free(ctx->K_bn);
    if (ctx->fixed_a) { free(ctx->fixed_a); }
    free(ctx);
}

int gsa_srp_set_fixed_a(gsa_srp_ctx *ctx, const uint8_t *a, size_t a_len) {
    if (!ctx || !a || !a_len) return -1;
    free(ctx->fixed_a);
    ctx->fixed_a = malloc(a_len);
    if (!ctx->fixed_a) return -1;
    memcpy(ctx->fixed_a, a, a_len);
    ctx->fixed_a_len = a_len;
    return 0;
}

int gsa_srp_start(gsa_srp_ctx *ctx, uint8_t *out, size_t *a_len) {
    if (!ctx || !a_len) return -1;
    size_t width = bn_bytes(ctx->N); /* 256 for 2048-bit */
    if (!out) { *a_len = width; return 0; }

    BN_CTX *bnctx = BN_CTX_new();
    if (!bnctx) return -1;
    int rc = -1;

    if (!ctx->a) ctx->a = BN_new();
    if (!ctx->A) ctx->A = BN_new();
    if (!ctx->a || !ctx->A) goto done;

    if (ctx->fixed_a) {
        if (!BN_bin2bn(ctx->fixed_a, (int)ctx->fixed_a_len, ctx->a)) goto done;
    } else {
        /* 256-bit random private exponent. */
        if (!BN_rand(ctx->a, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) goto done;
    }
    if (!BN_mod_exp(ctx->A, ctx->g, ctx->a, ctx->N, bnctx)) goto done;

    if (*a_len < width) goto done;
    if (BN_bn2binpad(ctx->A, out, (int)width) < 0) goto done;
    *a_len = width;
    rc = 0;
done:
    BN_CTX_free(bnctx);
    return rc;
}

int gsa_srp_s2k(const char *password,
                const uint8_t *salt, size_t salt_len,
                uint32_t iterations,
                int is_s2k_fo,
                uint8_t out_key[32]) {
    if (!password) return -1;

    uint8_t pwhash[GSA_SHA256_LEN];
    gsa_sha256((const uint8_t *)password, strlen(password), pwhash);

    /* s2k: use the 32-byte digest directly.
     * s2k_fo: use its lowercase hex expansion (64 bytes). */
    uint8_t hexbuf[GSA_SHA256_LEN * 2];
    const uint8_t *d;
    size_t dlen;
    if (is_s2k_fo) {
        static const char H[] = "0123456789abcdef";
        for (size_t i = 0; i < GSA_SHA256_LEN; i++) {
            hexbuf[i * 2 + 0] = (uint8_t)H[(pwhash[i] >> 4) & 0xF];
            hexbuf[i * 2 + 1] = (uint8_t)H[(pwhash[i]) & 0xF];
        }
        d = hexbuf;
        dlen = sizeof(hexbuf);
    } else {
        d = pwhash;
        dlen = GSA_SHA256_LEN;
    }
    return gsa_pbkdf2_hmac_sha256(d, dlen, salt, salt_len, iterations, out_key, 32);
}

int gsa_srp_process(gsa_srp_ctx *ctx,
                    const char *username,
                    const uint8_t *password_key, size_t password_key_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *B_bytes, size_t B_len,
                    uint8_t out_m1[32]) {
    if (!ctx || !ctx->A || !ctx->a) return -1;

    BN_CTX *bnctx = BN_CTX_new();
    if (!bnctx) return -1;
    int rc = -1;

    BIGNUM *B = BN_bin2bn(B_bytes, (int)B_len, NULL);
    BIGNUM *x = BN_new(), *u = BN_new(), *k = BN_new();
    BIGNUM *S = BN_new(), *tmp = BN_new(), *tmp2 = BN_new(), *exp = BN_new();
    uint8_t *A_pad = NULL, *B_pad = NULL, *g_pad = NULL, *N_pad = NULL;
    size_t width = bn_bytes(ctx->N);

    if (!B || !x || !u || !k || !S || !tmp || !tmp2 || !exp) goto done;

    /* k = H(N | PAD(g)) */
    if (bn_to_padded(ctx->N, width, &N_pad)) goto done;
    if (bn_to_padded(ctx->g, width, &g_pad)) goto done;
    {
        uint8_t kh[GSA_SHA256_LEN];
        sha256_cat(N_pad, width, g_pad, width, kh);
        if (!BN_bin2bn(kh, sizeof(kh), k)) goto done;
    }

    /* u = H(PAD(A) | PAD(B)) */
    if (bn_to_padded(ctx->A, width, &A_pad)) goto done;
    if (bn_to_padded(B, width, &B_pad)) goto done;
    {
        uint8_t uh[GSA_SHA256_LEN];
        sha256_cat(A_pad, width, B_pad, width, uh);
        if (!BN_bin2bn(uh, sizeof(uh), u)) goto done;
    }

    /* x = H(salt | H(password_key))   [noUsernameInX] */
    {
        uint8_t inner[GSA_SHA256_LEN];
        gsa_sha256(password_key, password_key_len, inner);
        uint8_t xh[GSA_SHA256_LEN];
        sha256_cat(salt, salt_len, inner, sizeof(inner), xh);
        if (!BN_bin2bn(xh, sizeof(xh), x)) goto done;
    }
    (void)username; /* NOT folded into x (noUsernameInX); used in M1 below */

    /* S = (B - k * g^x)^(a + u*x) mod N */
    if (!BN_mod_exp(tmp, ctx->g, x, ctx->N, bnctx)) goto done;      /* g^x */
    if (!BN_mod_mul(tmp, k, tmp, ctx->N, bnctx)) goto done;          /* k*g^x */
    if (!BN_mod_sub(tmp2, B, tmp, ctx->N, bnctx)) goto done;         /* B - k*g^x */
    if (!BN_mul(exp, u, x, bnctx)) goto done;                        /* u*x */
    if (!BN_add(exp, exp, ctx->a)) goto done;                        /* a + u*x */
    if (!BN_mod_exp(S, tmp2, exp, ctx->N, bnctx)) goto done;         /* S */

    /* K = H(S) */
    {
        uint8_t *S_pad = NULL;
        if (bn_to_padded(S, width, &S_pad)) goto done;
        gsa_sha256(S_pad, width, ctx->K);
        free(S_pad);
        ctx->have_K = 1;
    }

    /* M1 = H( H(N) XOR H(g) | H(I) | salt | A | B | K )
     * NOTE: H(I) inclusion under noUsernameInX is VALIDATION-PENDING. */
    {
        uint8_t hN[GSA_SHA256_LEN], hg[GSA_SHA256_LEN], hxor[GSA_SHA256_LEN];
        gsa_sha256(N_pad, width, hN);
        gsa_sha256(g_pad, width, hg);
        for (size_t i = 0; i < GSA_SHA256_LEN; i++) hxor[i] = hN[i] ^ hg[i];

        uint8_t hI[GSA_SHA256_LEN];
        gsa_sha256((const uint8_t *)(username ? username : ""),
                   username ? strlen(username) : 0, hI);

        sha256_stream c;
        sha256_begin(&c);
        sha256_add(&c, hxor, sizeof(hxor));
        sha256_add(&c, hI, sizeof(hI));
        sha256_add(&c, salt, salt_len);
        sha256_add(&c, A_pad, width);
        sha256_add(&c, B_pad, width);
        sha256_add(&c, ctx->K, sizeof(ctx->K));
        sha256_end(&c, ctx->M1);
        ctx->have_M1 = 1;
        memcpy(out_m1, ctx->M1, GSA_SHA256_LEN);
    }

    rc = 0;
done:
    BN_free(B); BN_clear_free(x); BN_free(u); BN_free(k);
    BN_clear_free(S); BN_free(tmp); BN_free(tmp2); BN_clear_free(exp);
    free(A_pad); free(B_pad); free(g_pad); free(N_pad);
    BN_CTX_free(bnctx);
    return rc;
}

int gsa_srp_verify(gsa_srp_ctx *ctx, const uint8_t M2[32]) {
    if (!ctx || !ctx->have_M1 || !ctx->have_K || !ctx->A) return -1;

    /* M2 = H( PAD(A) | M1 | K ) */
    size_t width = bn_bytes(ctx->N);
    uint8_t *A_pad = NULL;
    if (bn_to_padded(ctx->A, width, &A_pad)) return -1;

    uint8_t expected[GSA_SHA256_LEN];
    sha256_stream c;
    sha256_begin(&c);
    sha256_add(&c, A_pad, width);
    sha256_add(&c, ctx->M1, sizeof(ctx->M1));
    sha256_add(&c, ctx->K, sizeof(ctx->K));
    sha256_end(&c, expected);
    free(A_pad);

    return gsa_consttime_eq(expected, M2, GSA_SHA256_LEN) == 1 ? 0 : -1;
}

int gsa_srp_session_key(gsa_srp_ctx *ctx, uint8_t *out, size_t *key_len) {
    if (!ctx || !key_len) return -1;
    if (!out) { *key_len = GSA_SHA256_LEN; return 0; }
    if (!ctx->have_K || *key_len < GSA_SHA256_LEN) return -1;
    memcpy(out, ctx->K, GSA_SHA256_LEN);
    *key_len = GSA_SHA256_LEN;
    return 0;
}
