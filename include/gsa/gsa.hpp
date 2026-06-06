/*
 * gsa/gsa.hpp — C++ convenience wrapper over the libgsa C ABI.
 *
 * Header-only RAII niceties (std::string / std::vector), so C++ callers like
 * AltSign can use libgsa without juggling malloc/free. The C ABI in the *.h
 * headers remains the source of truth and is what other languages bind to.
 */
#ifndef GSA_GSA_HPP
#define GSA_GSA_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "gsa/crypto.h"
#include "gsa/srp.h"

namespace gsa {

using Bytes = std::vector<uint8_t>;
using Digest = std::array<uint8_t, GSA_SHA256_LEN>;

inline Digest sha256(const uint8_t *data, size_t len) {
    Digest out{};
    gsa_sha256(data, len, out.data());
    return out;
}
inline Digest sha256(const Bytes &d) { return sha256(d.data(), d.size()); }

inline Digest hmac_sha256(const Bytes &key, const Bytes &data) {
    Digest out{};
    gsa_hmac_sha256(key.data(), key.size(), data.data(), data.size(), out.data());
    return out;
}

inline Bytes pbkdf2_hmac_sha256(const Bytes &password, const Bytes &salt,
                                uint32_t iterations, size_t out_len) {
    Bytes out(out_len);
    if (gsa_pbkdf2_hmac_sha256(password.data(), password.size(),
                               salt.data(), salt.size(), iterations,
                               out.data(), out.size()) != 0) {
        throw std::runtime_error("gsa: pbkdf2 failed");
    }
    return out;
}

inline bool consttime_eq(const Bytes &a, const Bytes &b) {
    return a.size() == b.size() &&
           gsa_consttime_eq(a.data(), b.data(), a.size()) == 1;
}

/* RAII SRP client. */
class Srp {
public:
    Srp() : ctx_(gsa_srp_new()) {
        if (!ctx_) throw std::runtime_error("gsa: srp ctx alloc failed");
    }
    ~Srp() { if (ctx_) gsa_srp_free(ctx_); }
    Srp(const Srp &) = delete;
    Srp &operator=(const Srp &) = delete;

    Bytes start() {
        size_t n = 0;
        gsa_srp_start(ctx_, nullptr, &n);
        Bytes a(n);
        if (gsa_srp_start(ctx_, a.data(), &n) != 0)
            throw std::runtime_error("gsa: srp_start failed");
        a.resize(n);
        return a;
    }

    static Bytes s2k(const std::string &password, const Bytes &salt,
                     uint32_t iterations, bool is_s2k_fo) {
        Bytes key(32);
        if (gsa_srp_s2k(password.c_str(), salt.data(), salt.size(),
                        iterations, is_s2k_fo ? 1 : 0, key.data()) != 0)
            throw std::runtime_error("gsa: s2k failed");
        return key;
    }

    Digest process(const std::string &username, const Bytes &password_key,
                   const Bytes &salt, const Bytes &B) {
        Digest m1{};
        if (gsa_srp_process(ctx_, username.c_str(),
                            password_key.data(), password_key.size(),
                            salt.data(), salt.size(),
                            B.data(), B.size(), m1.data()) != 0)
            throw std::runtime_error("gsa: srp_process failed");
        return m1;
    }

    bool verify(const Digest &M2) { return gsa_srp_verify(ctx_, M2.data()) == 0; }

    Bytes session_key() {
        size_t n = 0;
        gsa_srp_session_key(ctx_, nullptr, &n);
        Bytes k(n);
        if (gsa_srp_session_key(ctx_, k.data(), &n) != 0)
            throw std::runtime_error("gsa: session_key unavailable");
        k.resize(n);
        return k;
    }

    gsa_srp_ctx *raw() { return ctx_; }

private:
    gsa_srp_ctx *ctx_;
};

} // namespace gsa

#endif /* GSA_GSA_HPP */
