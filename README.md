# libgsa

**A corecrypto-free implementation of Apple's GrandSlam (GSA) authentication, in
C/C++ on OpenSSL.**

`libgsa` reimplements the cryptography and the SRP-6a login handshake that
AltSign / AltServer use to authenticate with Apple's Developer-portal servers —
*without* Apple's `corecrypto`. It depends only on OpenSSL (already present in
every AltServer-Linux build) and, optionally, `libplist`. Drop it into an
AltSign-style codebase to delete the entire `corecrypto` fetch/compile/link
stage.

> Status: **early / spike.** The OpenSSL crypto primitives are implemented and
> covered by RFC/NIST test vectors. The Apple-variant SRP and the end-to-end
> handshake are being validated differentially against `corecrypto` and against
> the existing open reimplementations (see *Correctness*). Not yet
> production-ready.

## Why this exists

Every C/C++ AltServer-Linux fork still statically links Apple's `corecrypto`,
which:

- ships under Apple's **corecrypto Internal Use License** (90-day, internal-use,
  security-verification only, **no redistribution**) — so it can never be baked
  into a redistributable binary;
- is fetched live from `developer.apple.com` at build time, and Apple silently
  revs it (it broke once already when the zip started extracting to
  `corecrypto-2024/`).

There are reimplementations of this exact flow in **Rust** (SideStore
`apple-private-apis`), **Python** (JJTech0130 `pypush`) and **D** (Dadoum
`Provision`/`Sideloader`) — but **none in C/C++**. `libgsa` fills that gap so the
whole AltServer-Linux ecosystem can drop `corecrypto`.

## Is this legal?

Yes — this is the *clean* path, not the risky one.

- **We do not ship, copy, or redistribute any Apple code.** `corecrypto` source
  is never vendored here.
- We reimplement a **protocol** (GrandSlam SRP-6a) on standard, redistributable
  crypto (OpenSSL) using published specs — RFC 5054 (SRP), RFC 2945, RFC 6070
  (PBKDF2), NIST AES/GCM. Protocols and APIs are not copyrightable
  (*Google v. Oracle*, 2021); only an *implementation* is, and this is an
  independent implementation.
- The open reimplementations are read as **specification only** (clean-room) —
  no source is copied — so this library keeps its own permissive license.

Caveat: this library *talks to* Apple's private auth servers, so **Apple
Developer Program terms** govern your *use* of it (exactly as they do for
AltStore / AltServer). That's a constraint on the operator, not a distribution
problem with the code. Use a secondary Apple ID.

## What it covers

| Layer | What | Deps |
| --- | --- | --- |
| `gsa/crypto.h` | SHA-256, HMAC, PBKDF2-HMAC-SHA256, AES-256-CBC+PKCS7, AES-256-GCM, constant-time compare | OpenSSL |
| `gsa/srp.h` | SRP-6a client, **Apple variant** (RFC 5054 2048-bit group, SHA-256, `noUsernameInX`, `s2k`/`s2k_fo` password hashing) | OpenSSL |
| `gsa/gsa.h` | The GrandSlam handshake state machine (builds/parses the auth plists, derives session keys, decrypts `spd`/`et`, yields adsid + app token). **Transport-injected** — you supply the HTTP + anisette callbacks. | libplist (optional) |

It deliberately does **not** include an HTTP client or an anisette/ADI provider —
those are injected by the caller — which keeps `libgsa` tiny and reusable.
(Anisette is a *separate* Apple dependency; replacing `corecrypto` does not
replace it.)

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

On macOS (Apple Silicon), point CMake at the arm64 Homebrew OpenSSL so it
doesn't pick up an x86_64 one:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

Options:

- `-DGSA_BUILD_TESTS=ON` (default) — build the vector/differential tests.
- `-DGSA_DIFF_CORECRYPTO=/path/to/libcorecrypto_static.a` — also build the
  differential harness that diffs `libgsa` SRP output byte-for-byte against
  Apple's `corecrypto` (for local correctness validation only; never shipped).

## Correctness (how we prove it's right)

Crypto is byte-deterministic, so this is testable without ever calling Apple:

1. **Primitive vectors** (`tests/test_primitives.c`) — PBKDF2 (RFC 6070), HMAC
   (RFC 4231), AES-CBC / AES-GCM (NIST KAT). Run in CI, no Apple, no network.
2. **SRP vectors + differential** (`tests/test_srp.c`) — RFC 5054 Appendix B
   fixed-`a`/`b` vector, plus an optional byte-for-byte diff against
   `corecrypto` with a pinned RNG. The Apple-specific `noUsernameInX` /
   `s2k` behavior is frozen as golden files derived once from `corecrypto` and
   cross-checked against `pypush`.
3. **Recorded transcript replay** (`tests/test_transcript.c`) — replay one
   captured GSA handshake offline and assert the same session key / decrypted
   token, with zero Apple contact.
4. **Live acceptance** (manual) — build AltServer with `-lcorecrypto_static`
   removed, authenticate with a test Apple ID, sign + launch on a device with no
   `Code=85`.

## Credits / references (read as spec, not copied)

- JJTech0130 / **pypush** — clearest reference for the GSA SRP variant.
- SideStore / **apple-private-apis** (`icloud-auth`, MPL-2.0) — Rust analogue.
- Dadoum / **Provision** + **Sideloader** — D reimplementation.
- The AltStore project (NyaMisty's AltSign-Linux) — the original corecrypto-based
  flow this replaces.

## License

MIT — see [LICENSE](LICENSE).
