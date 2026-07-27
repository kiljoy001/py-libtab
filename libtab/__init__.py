"""py-libtab — ctypes binding to objective-9c's real libtab C implementation.

An earlier pure-Python reimplementation of the .tab wire format was
removed: its SIGNED-column support silently produced cells that don't
verify under the real libtab.c (monocypher's EdDSA substitutes BLAKE2b
for SHA-512 throughout, so it isn't wire-compatible with standard
Ed25519 — see vendor/build.sh's history for how that was found). Rather
than ship a second, subtly-incompatible implementation of a format whose
whole point is exact interop with the C/Go implementations, this package
now wraps the actual C source directly.

See libtab.native for NativeTable and friends. Requires vendor/libtab.so
to be built first — run vendor/build.sh (needs a C toolchain; see
vendor/README).
"""

from .native import (
    LibtabNativeError,
    NativeColumn,
    NativeRow,
    NativeTable,
    NativeUnavailable,
    b64_decode,
    b64_encode,
    keypair,
    seal,
    unseal,
)

__all__ = [
    "LibtabNativeError",
    "NativeColumn",
    "NativeRow",
    "NativeTable",
    "NativeUnavailable",
    "b64_decode",
    "b64_encode",
    "keypair",
    "seal",
    "unseal",
]
