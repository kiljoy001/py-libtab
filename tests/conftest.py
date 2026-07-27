"""Shared fixtures and helpers for the test suite.

Consolidates boilerplate that PMD/CPD flagged as duplicated across test
files: the "native engine available" skip guard, the monocypher keypair
derivation, and the common typed-table setups. Tests import these
instead of re-deriving them.
"""

from __future__ import annotations

import os

import pytest

VENDOR_SO = os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")


def native_available() -> bool:
    """Whether the built native engine is importable and present. Test
    modules use this in their module-level skip guard instead of
    re-spelling the path check (the pattern CPD flagged in 12 files)."""
    if not os.path.exists(VENDOR_SO):
        return False
    try:
        import libtab.native  # noqa: F401
    except Exception:  # noqa: BLE001 - any failure means "unavailable"
        return False
    return True


def monocypher_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """Derive a deterministic keypair from `seed` for reproducible tests.

    Thin alias for the library's own seed helper (the ctypes derivation
    now lives in libtab, not here). Returns (secret_key[64],
    public_key[32]). See tests/test_crypto_vectors.py for why monocypher's
    EdDSA is BLAKE2b-based and NOT RFC 8032."""
    from libtab import native

    return native._keypair_from_seed(seed)


@pytest.fixture
def keypair():
    """A stable monocypher keypair (seed 0..31) as (sk64, pk32)."""
    return monocypher_keypair(bytes(range(32)))


@pytest.fixture
def signed_table(tmp_path):
    """A fresh table with an id column and a SIGNED `body` column, plus
    one row keyed id=a. Returns (table, row)."""
    from libtab import native

    t = native.NativeTable.create(
        str(tmp_path / "t.tab"),
        "t",
        [native.NativeColumn("id"), native.NativeColumn("body", type="SIGNED")],
    )
    r = t.add_row("id", "a")
    yield t, r
    t.close()


@pytest.fixture
def hashed_table(tmp_path):
    """A fresh table with an id column and a HASHED `pwhash` column, plus
    one row keyed id=a. Returns (table, row)."""
    from libtab import native

    t = native.NativeTable.create(
        str(tmp_path / "t.tab"),
        "t",
        [native.NativeColumn("id"), native.NativeColumn("pwhash", type="HASHED")],
    )
    r = t.add_row("id", "a")
    yield t, r
    t.close()
