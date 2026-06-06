/*
 * gsa/gsa.h — the GrandSlam (GSA) authentication handshake.
 *
 * Reproduces AltSign's AppleAPI::Authenticate end to end, but transport- and
 * anisette-agnostic: YOU provide the HTTP POST and the anisette headers, this
 * library does the SRP handshake, session-key derivation, spd/et decryption and
 * token extraction. That keeps libgsa free of any HTTP client or Apple ADI
 * dependency.
 *
 * Requires libplist (compile-time GSA_HAVE_PLIST). The crypto/SRP core works
 * without it.
 */
#ifndef GSA_GSA_H
#define GSA_GSA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- caller-supplied integrations ------------------------------------- */

/*
 * Anisette data: the X-Apple-I-MD* headers Apple requires. libgsa does NOT
 * generate these (that's a separate Apple dependency); the caller supplies them
 * from an anisette server / provider. All strings are NUL-terminated UTF-8.
 */
typedef struct {
    const char *machine_id;        /* X-Apple-I-MD-M */
    const char *one_time_password; /* X-Apple-I-MD   */
    const char *local_user_id;     /* X-Apple-I-MD-LU */
    uint32_t    routing_info;      /* X-Apple-I-MD-RINFO */
    const char *device_id;         /* X-Mme-Device-Id */
    const char *device_serial;     /* X-Apple-I-SRL-NO */
    const char *device_description;/* X-Mme-Client-Info */
    const char *locale;            /* e.g. "en_US" */
    const char *time_zone;         /* e.g. "GMT" */
    int64_t     client_time_unix;  /* X-Apple-I-Client-Time (epoch seconds) */
} gsa_anisette;

/*
 * HTTP transport callback. libgsa hands you a fully-formed request body
 * (an XML plist) plus the headers it wants set; you POST it to
 * `https://gsa.apple.com/grandslam/GsService2` and return the raw response body.
 *
 * Return 0 on success and fill *resp / *resp_len (allocated with malloc; libgsa
 * frees it). Non-zero on transport error.
 */
typedef int (*gsa_http_post_fn)(void *user,
                                const char *url,
                                const char *const *header_names,
                                const char *const *header_values,
                                size_t header_count,
                                const uint8_t *body, size_t body_len,
                                uint8_t **resp, size_t *resp_len);

/*
 * Two-factor code provider. Called when Apple requires a 2FA code; return the
 * 6-digit code into `out` (NUL-terminated). Return 0 on success, non-zero to
 * abort. May be NULL (then 2FA-required becomes an error).
 */
typedef int (*gsa_2fa_provider_fn)(void *user, char *out, size_t out_cap);

/* ---- request / result -------------------------------------------------- */

typedef struct {
    const char         *apple_id;
    const char         *password;
    gsa_anisette        anisette;
    gsa_http_post_fn    http_post;
    gsa_2fa_provider_fn twofa_provider; /* optional */
    void               *user;           /* opaque, passed back to callbacks */
} gsa_auth_request;

typedef struct {
    char *adsid;       /* Apple DS ID */
    char *gs_token;    /* the com.apple.gs.xcode.auth app token */
    char *idms_token;  /* GsIdmsToken */
} gsa_auth_result;

typedef enum {
    GSA_OK = 0,
    GSA_ERR_TRANSPORT = 1,
    GSA_ERR_INVALID_RESPONSE = 2,
    GSA_ERR_HANDSHAKE = 3,        /* SRP / decrypt failure */
    GSA_ERR_NEEDS_2FA = 4,        /* 2FA required and no provider given */
    GSA_ERR_BAD_2FA = 5,
    GSA_ERR_APPLE = 6,            /* Apple returned an error status */
    GSA_ERR_NO_PLIST = 7,         /* built without libplist */
    GSA_ERR_INTERNAL = 8,
} gsa_status;

/*
 * Perform the full GrandSlam authentication. On GSA_OK, `*out` is populated and
 * must be released with gsa_auth_result_free(). `apple_err_code`/`apple_err_msg`
 * (optional) receive Apple's status code/message on GSA_ERR_APPLE.
 */
gsa_status gsa_authenticate(const gsa_auth_request *req,
                            gsa_auth_result *out,
                            int64_t *apple_err_code,
                            char **apple_err_msg);

void gsa_auth_result_free(gsa_auth_result *r);

const char *gsa_status_str(gsa_status s);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GSA_GSA_H */
