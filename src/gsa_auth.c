/*
 * gsa_auth.c — the GrandSlam (GSA) handshake state machine.
 *
 * Reproduces AltSign's AppleAPI::Authenticate, transport-injected. Built only
 * when libplist is available (GSA_HAVE_PLIST). The SRP + crypto core lives in
 * srp_openssl.c / crypto_openssl.c and is independently testable.
 *
 * IMPLEMENTATION STATUS: skeleton. The request/response plist plumbing is
 * staged out below with explicit TODOs keyed to the reference flow
 * (pypush gsa.py / SideStore icloud-auth). Wire it up against a recorded
 * transcript (tests/test_transcript.c) before trusting it live.
 */
#include "gsa/gsa.h"
#include "gsa/srp.h"
#include "gsa/crypto.h"

#include <stdlib.h>
#include <string.h>

const char *gsa_status_str(gsa_status s) {
    switch (s) {
        case GSA_OK:                   return "ok";
        case GSA_ERR_TRANSPORT:        return "transport error";
        case GSA_ERR_INVALID_RESPONSE: return "invalid response";
        case GSA_ERR_HANDSHAKE:        return "handshake/decrypt failure";
        case GSA_ERR_NEEDS_2FA:        return "two-factor required";
        case GSA_ERR_BAD_2FA:          return "two-factor rejected";
        case GSA_ERR_APPLE:            return "apple error status";
        case GSA_ERR_NO_PLIST:         return "built without libplist";
        case GSA_ERR_INTERNAL:         return "internal error";
        default:                       return "unknown";
    }
}

void gsa_auth_result_free(gsa_auth_result *r) {
    if (!r) return;
    free(r->adsid);     r->adsid = NULL;
    free(r->gs_token);  r->gs_token = NULL;
    free(r->idms_token);r->idms_token = NULL;
}

#ifndef GSA_HAVE_PLIST

gsa_status gsa_authenticate(const gsa_auth_request *req, gsa_auth_result *out,
                            int64_t *apple_err_code, char **apple_err_msg) {
    (void)req; (void)out; (void)apple_err_code; (void)apple_err_msg;
    return GSA_ERR_NO_PLIST;
}

#else /* GSA_HAVE_PLIST */

#include <plist/plist.h>

/*
 * Session-key derivation used after a successful SRP exchange (matches
 * ALTCreateSessionKey): key = HMAC-SHA256(srp_session_key, label).
 * Labels Apple uses: "extra data key:", "extra data iv:", "HMAC key:".
 */
static void derive_session_key(const uint8_t *sk, size_t sk_len,
                               const char *label, uint8_t out[32]) {
    gsa_hmac_sha256(sk, sk_len, (const uint8_t *)label, strlen(label), out);
}

/*
 * Decrypt the "spd" blob (CBC). key/iv derived via derive_session_key with
 * "extra data key:" / "extra data iv:". Mirrors ALTDecryptDataCBC.
 */
static int decrypt_spd(const uint8_t *sk, size_t sk_len,
                       const uint8_t *spd, size_t spd_len,
                       uint8_t *out, size_t *out_len) {
    uint8_t key[32], iv32[32];
    derive_session_key(sk, sk_len, "extra data key:", key);
    derive_session_key(sk, sk_len, "extra data iv:", iv32);
    /* CBC IV is the first 16 bytes of the derived "iv" key. */
    return gsa_aes256_cbc_pkcs7_decrypt(key, iv32, spd, spd_len, out, out_len);
}

/*
 * Decrypt the "et" GCM app token (matches ALTDecryptDataGCM):
 *   layout: [3-byte version "XYZ"][16-byte IV][ciphertext][16-byte tag]
 *   AAD    = the 3 version bytes; key = the GSA session key (sk).
 */
static int decrypt_et(const uint8_t *sk, size_t sk_len,
                      const uint8_t *et, size_t et_len,
                      uint8_t *out, size_t *out_len) {
    if (et_len < 3 + 16 + 16) return -1;
    const uint8_t *version = et;             /* 3 bytes AAD */
    const uint8_t *iv = et + 3;              /* 16 bytes */
    const uint8_t *ct = et + 3 + 16;
    size_t ct_len = et_len - 3 - 16 - 16;
    const uint8_t *tag = et + et_len - 16;
    if (gsa_aes256_gcm_decrypt(sk /* must be 32 */, iv, 16,
                               version, 3, ct, ct_len, tag, out) != 0)
        return -1;
    (void)sk_len;
    *out_len = ct_len;
    return 0;
}

gsa_status gsa_authenticate(const gsa_auth_request *req, gsa_auth_result *out,
                            int64_t *apple_err_code, char **apple_err_msg) {
    if (!req || !out || !req->http_post) return GSA_ERR_INTERNAL;
    memset(out, 0, sizeof(*out));
    if (apple_err_code) *apple_err_code = 0;
    if (apple_err_msg)  *apple_err_msg = NULL;

    gsa_srp_ctx *srp = gsa_srp_new();
    if (!srp) return GSA_ERR_INTERNAL;
    gsa_status st = GSA_ERR_INTERNAL;

    /* ---- step 1: init — send A2k ----------------------------------------
     * TODO(transcript): build the "init" GsService2 request plist:
     *   Header.Version="1.0.1"; Request{ A2k=<A>, ps=["s2k","s2k_fo"],
     *   cpd=<client+anisette dict>, u=appleID, o="init" }.
     * gsa_srp_start(srp, A, &alen) gives A. POST via req->http_post, parse
     * Response → sp, s (salt), i (iterations), B.
     */

    /* ---- step 2: complete — send M1 -------------------------------------
     * TODO(transcript):
     *   is_s2k_fo = (sp == "s2k_fo");
     *   gsa_srp_s2k(req->password, salt, iters, is_s2k_fo, key);
     *   gsa_srp_process(srp, req->apple_id, key, salt, B, M1);
     *   POST { c=<c>, M1=<M1>, cpd, u=appleID, o="complete" } → Response.
     *   gsa_srp_verify(srp, M2). Then decrypt_spd() the "spd" → adsid,
     *   GsIdmsToken. Handle Status.au == "trustedDeviceSecondaryAuth" → 2FA
     *   (call req->twofa_provider, then re-run from step 1).
     */

    /* ---- step 3: apptokens — fetch the Xcode auth token -----------------
     * TODO(transcript):
     *   checksum = HMAC-SHA256(sk, "apptokens"||adsid||"com.apple.gs.xcode.auth")
     *             (matches ALTCreateAppTokensChecksum).
     *   POST { u=adsid, app=[...], c=<c>, t=idmsToken, checksum, cpd,
     *          o="apptokens" } → "et"; decrypt_et(sk, et) → token plist →
     *   out->gs_token.
     */

    (void)decrypt_spd; (void)decrypt_et; /* used once steps are wired */

    gsa_srp_free(srp);
    return st;
}

#endif /* GSA_HAVE_PLIST */
