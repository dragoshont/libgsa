#!/usr/bin/env python3
"""
gsa_oracle.py — generate golden SRP vectors for the Apple GrandSlam variant.

This is an INDEPENDENT oracle. It uses the MIT-licensed `srp` PyPI package
(`srp._pysrp`) configured exactly as a real Apple GSA client configures it:

    srp.rfc5054_enable()        # PAD(N)/PAD(g)/PAD(A)/PAD(B) in k and u
    srp.no_username_in_x()      # drop username from x (": " separator kept)

The `srp` library is the same SRP-6a implementation that authenticates live
against Apple's GrandSlam servers in community clients, so its numeric output
is ground truth for what Apple's corecrypto produces — without using any Apple
code. We drive it with a FIXED client private exponent `a` so the result is
fully deterministic, then emit the bytes as a C header.

The emitted numbers (A, M1, K, M2) are not Apple code and not copyrightable;
they are committed as tests/vectors/apple_srp_vector.h so the C test suite can
assert libgsa is byte-for-byte identical without needing Python at build time.

Usage:
    python3 tests/oracle/gsa_oracle.py            # print vector + write header
    python3 tests/oracle/gsa_oracle.py --check    # print only, no write
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import sys

try:
    import srp._pysrp as srp
except ImportError:
    sys.stderr.write(
        "error: the `srp` package is required.\n"
        "       pip install srp pbkdf2\n"
    )
    sys.exit(2)

# --- Apple GSA compatibility flags (exactly as a real GSA client sets them) ---
srp.rfc5054_enable()
srp.no_username_in_x()

HEADER_PATH = os.path.join(
    os.path.dirname(__file__), "..", "vectors", "apple_srp_vector.h"
)

# --- Deterministic, self-contained test inputs ------------------------------
# These are arbitrary fixed values; none are real credentials.
USERNAME = "test@example.com"
PASSWORD = "correct horse battery staple"
SALT = bytes.fromhex(
    "0102030405060708090a0b0c0d0e0f101112131415161718"
    "191a1b1c1d1e1f20"
)  # 32-byte salt
ITERATIONS = 1000

# A fixed 256-byte client private exponent `a` (high bit set -> A is full width).
FIXED_A = bytes([0x80]) + bytes(range(1, 256))  # 256 bytes, deterministic
assert len(FIXED_A) == 256

# A fixed 256-byte server public value B (high bit set -> full width, B % N != 0).
FIXED_B = bytes([0xC3]) + bytes((i * 7 + 11) & 0xFF for i in range(255))
assert len(FIXED_B) == 256


def encrypt_password(password: str, salt: bytes, iterations: int) -> bytes:
    """s2k password key: PBKDF2-HMAC-SHA256(SHA256(password), salt, iters, 32)."""
    p = hashlib.sha256(password.encode("utf-8")).digest()
    return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, dklen=32)


def session_subkey(session_key: bytes, name: str) -> bytes:
    return hmac.new(session_key, name.encode(), hashlib.sha256).digest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="print only, do not write header")
    args = ap.parse_args()

    password_key = encrypt_password(PASSWORD, SALT, ITERATIONS)

    usr = srp.User(
        USERNAME,
        bytes(),
        hash_alg=srp.SHA256,
        ng_type=srp.NG_2048,
        bytes_a=FIXED_A,
    )
    _, A = usr.start_authentication()
    # Inject the s2k password key just like a real GSA client does once it has
    # the salt + iteration count from the server.
    usr.p = password_key
    M1 = usr.process_challenge(SALT, FIXED_B)
    if M1 is None:
        sys.stderr.write("error: process_challenge returned None (SRP safety check)\n")
        return 1
    K = usr.get_session_key_unverified() if hasattr(usr, "get_session_key_unverified") else usr.K
    # usr.K is the session key (H(S)); it's set after process_challenge.
    K = usr.K
    # M2 the server would send back to prove it:
    M2 = srp.calculate_H_AMK(usr.hash_class, usr.A, M1, usr.K)

    assert len(A) == 256, f"A not full width: {len(A)}"

    edk = session_subkey(K, "extra data key:")
    ediv = session_subkey(K, "extra data iv:")[:16]
    hmk = session_subkey(K, "HMAC key:")

    def hx(b: bytes) -> str:
        return b.hex()

    print(f"username   = {USERNAME}")
    print(f"password   = {PASSWORD}")
    print(f"salt       = {hx(SALT)}")
    print(f"iterations = {ITERATIONS}")
    print(f"a (fixed)  = {hx(FIXED_A)}")
    print(f"B (fixed)  = {hx(FIXED_B)}")
    print(f"pwkey      = {hx(password_key)}")
    print(f"A          = {hx(A)}")
    print(f"M1         = {hx(M1)}")
    print(f"K (session)= {hx(K)}")
    print(f"M2         = {hx(M2)}")
    print(f"edk        = {hx(edk)}")
    print(f"ediv       = {hx(ediv)}")
    print(f"hmk        = {hx(hmk)}")

    if args.check:
        return 0

    header = render_header(
        username=USERNAME,
        password=PASSWORD,
        salt=SALT,
        iterations=ITERATIONS,
        fixed_a=FIXED_A,
        fixed_b=FIXED_B,
        password_key=password_key,
        A=A,
        M1=M1,
        K=K,
        M2=M2,
        edk=edk,
        ediv=ediv,
        hmk=hmk,
    )
    out = os.path.normpath(HEADER_PATH)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        f.write(header)
    print(f"\nwrote {out}")
    return 0


def _carr(name: str, b: bytes) -> str:
    body = ", ".join(f"0x{x:02x}" for x in b)
    return f"static const uint8_t {name}[{len(b)}] = {{ {body} }};\n"


def render_header(**v) -> str:
    lines = []
    lines.append("/* AUTO-GENERATED by tests/oracle/gsa_oracle.py — DO NOT EDIT BY HAND.\n")
    lines.append(" *\n")
    lines.append(" * Golden SRP-6a vector for the Apple GrandSlam variant, produced by the\n")
    lines.append(" * MIT `srp` library (rfc5054 + no_username_in_x). These are numbers, not\n")
    lines.append(" * Apple code. Regenerate with:  python3 tests/oracle/gsa_oracle.py\n")
    lines.append(" */\n")
    lines.append("#ifndef GSA_APPLE_SRP_VECTOR_H\n")
    lines.append("#define GSA_APPLE_SRP_VECTOR_H\n\n")
    lines.append("#include <stdint.h>\n\n")
    lines.append(f'static const char GSA_VEC_USERNAME[] = "{v["username"]}";\n')
    lines.append(f'static const char GSA_VEC_PASSWORD[] = "{v["password"]}";\n')
    lines.append(f'static const uint32_t GSA_VEC_ITERATIONS = {v["iterations"]};\n\n')
    lines.append(_carr("GSA_VEC_SALT", v["salt"]))
    lines.append(_carr("GSA_VEC_FIXED_A", v["fixed_a"]))
    lines.append(_carr("GSA_VEC_FIXED_B", v["fixed_b"]))
    lines.append(_carr("GSA_VEC_PWKEY", v["password_key"]))
    lines.append(_carr("GSA_VEC_A", v["A"]))
    lines.append(_carr("GSA_VEC_M1", v["M1"]))
    lines.append(_carr("GSA_VEC_K", v["K"]))
    lines.append(_carr("GSA_VEC_M2", v["M2"]))
    lines.append(_carr("GSA_VEC_EDK", v["edk"]))
    lines.append(_carr("GSA_VEC_EDIV", v["ediv"]))
    lines.append(_carr("GSA_VEC_HMK", v["hmk"]))
    lines.append("\n#endif /* GSA_APPLE_SRP_VECTOR_H */\n")
    return "".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
