"""py-libtab — ctypes binding to objective-9c's real libtab C implementation.

An earlier pure-Python reimplementation of the .tab wire format was
removed: its SIGNED-column support silently produced cells that don't
verify under the real libtab.c (monocypher's EdDSA substitutes BLAKE2b
for SHA-512 throughout, so it isn't wire-compatible with standard
Ed25519 — see vendor/build.sh's history for how that was found). Rather
than ship a second, subtly-incompatible implementation of a format whose
whole point is exact interop with the C/Go implementations, this package
now wraps the actual C source directly.

See libtab.native for the Tabula type and friends. Requires
vendor/libtab.so to be built first — run vendor/build.sh (needs a C
toolchain; see vendor/README).
"""

from .native import (
    TabulaError,
    Column,
    Row,
    Tabula,
    TabulaUnavailable,
    b64_decode,
    b64_encode,
    keypair,
    seal,
    unseal,
)

# Deprecated 0.1.0 names. The public types were renamed to o9's Tabula
# vocabulary (a .tab file is a Tabula); the old "Native*" names only ever
# distinguished the FFI backend from a since-removed pure-Python one, so
# they leaked a dead implementation detail. Kept as aliases so 0.1.0
# imports don't hard-break; prefer the new names — these will be removed
# in a future release.
NativeTable = Tabula
NativeColumn = Column
NativeRow = Row
NativeError = TabulaError
NativeUnavailable = TabulaUnavailable

__all__ = [
    "TabulaError",
    "Column",
    "Row",
    "Tabula",
    "TabulaUnavailable",
    "b64_decode",
    "b64_encode",
    "keypair",
    "seal",
    "unseal",
    # deprecated aliases
    "NativeTable",
    "NativeColumn",
    "NativeRow",
    "NativeError",
    "NativeUnavailable",
]
