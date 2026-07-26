"""Known-answer / cross-reference tests for the C crypto primitives.

Distinct from the functional tests (which check "set then verify round-
trips"): these check the C library produces the *correct, specific*
output, against an independent reference. A miscompiled monocypher, a
wrong-endianness bug, or a subtly broken KDF would round-trip fine with
itself yet be wrong — only a known-answer check catches that.

- BLAKE2b: reference is Python's stdlib hashlib.blake2b (itself the
  reference BLAKE2 implementation). Exact-match required.
- Ed25519: monocypher uses a BLAKE2b-based EdDSA variant (NOT RFC 8032
  SHA-512), so there is no external reference; we assert internal
  consistency (sign→check) AND that a known seed yields a stable,
  pinned public key + signature (regression vector), so a future
  monocypher change that alters output is caught.
- argon2id: reference is argon2-cffi's low_level.hash_secret_raw with
  identical params + salt, compared against the digest libtab embeds in
  a HASHED cell. Exact-match required.
"""

from __future__ import annotations

import ctypes
import hashlib
import os

import pytest

native = pytest.importorskip("libtab.native")

if not os.path.exists(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")
):
    pytest.skip("vendor/libtab.so not built — run vendor/build.sh", allow_module_level=True)


@pytest.fixture(scope="module")
def lib():
    return native._get_lib()


# ---------------------------------------------------------------- BLAKE2b


def _blake2b(lib, msg: bytes, n: int) -> bytes:
    lib.crypto_blake2b.restype = None
    lib.crypto_blake2b.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t
    ]
    out = ctypes.create_string_buffer(n)
    lib.crypto_blake2b(out, n, msg, len(msg))
    return out.raw[:n]


@pytest.mark.parametrize("msg", [b"", b"abc", b"a" * 1, b"\x00" * 64, os.urandom(200)])
@pytest.mark.parametrize("n", [32, 64])
def test_blake2b_matches_reference(lib, msg, n):
    assert _blake2b(lib, msg, n) == hashlib.blake2b(msg, digest_size=n).digest()


def test_blake2b_256_abc_pinned_vector(lib):
    # BLAKE2b-256("abc"), a fixed regression vector (also == hashlib).
    assert _blake2b(lib, b"abc", 32).hex() == hashlib.blake2b(
        b"abc", digest_size=32
    ).hexdigest()


# --------------------------------------------------------------- Ed25519
# monocypher's crypto_eddsa_* is a BLAKE2b-based variant; pin it.


def _monocypher_keypair(lib, seed: bytes):
    lib.crypto_eddsa_key_pair.restype = None
    lib.crypto_eddsa_key_pair.argtypes = [
        ctypes.c_char * 64, ctypes.c_char * 32, ctypes.c_char * 32
    ]
    sk = (ctypes.c_char * 64)()
    pk = (ctypes.c_char * 32)()
    sd = (ctypes.c_char * 32)(*[bytes([b]) for b in seed])
    lib.crypto_eddsa_key_pair(sk, pk, sd)
    return bytes(sk), bytes(pk)


def _eddsa_sign(lib, sk: bytes, msg: bytes) -> bytes:
    lib.crypto_eddsa_sign.restype = None
    lib.crypto_eddsa_sign.argtypes = [
        ctypes.c_char * 64, ctypes.c_char * 64, ctypes.c_char_p, ctypes.c_size_t
    ]
    sig = (ctypes.c_char * 64)()
    skbuf = (ctypes.c_char * 64)(*[bytes([b]) for b in sk])
    lib.crypto_eddsa_sign(sig, skbuf, msg, len(msg))
    return bytes(sig)


def _eddsa_check(lib, sig: bytes, pk: bytes, msg: bytes) -> int:
    lib.crypto_eddsa_check.restype = ctypes.c_int
    lib.crypto_eddsa_check.argtypes = [
        ctypes.c_char * 64, ctypes.c_char * 32, ctypes.c_char_p, ctypes.c_size_t
    ]
    sigbuf = (ctypes.c_char * 64)(*[bytes([b]) for b in sig])
    pkbuf = (ctypes.c_char * 32)(*[bytes([b]) for b in pk])
    return lib.crypto_eddsa_check(sigbuf, pkbuf, msg, len(msg))


def test_eddsa_sign_check_consistency(lib):
    sk, pk = _monocypher_keypair(lib, bytes(range(32)))
    msg = b"the quick brown fox"
    sig = _eddsa_sign(lib, sk, msg)
    assert _eddsa_check(lib, sig, pk, msg) == 0  # 0 == valid in monocypher


def test_eddsa_rejects_tampered_message(lib):
    sk, pk = _monocypher_keypair(lib, bytes(range(32)))
    sig = _eddsa_sign(lib, sk, b"original")
    assert _eddsa_check(lib, sig, pk, b"tampered") != 0


def test_eddsa_pinned_vector(lib):
    # Regression vector: seed = 0..31 must always yield this exact public
    # key and signature over b"vector". If monocypher's EdDSA output ever
    # changes (e.g. an accidental switch to SHA-512), this fails loudly.
    sk, pk = _monocypher_keypair(lib, bytes(range(32)))
    sig = _eddsa_sign(lib, sk, b"vector")
    # Pinned by observing the current build once and freezing it.
    assert len(pk) == 32
    assert len(sig) == 64
    assert _eddsa_check(lib, sig, pk, b"vector") == 0
    # store hex so a change is a visible diff, not just a boolean
    assert pk.hex() == _PINNED_PK
    assert sig.hex() == _PINNED_SIG


# Pinned once from the current libtab-linked monocypher (seed 0..31,
# message b"vector"). A change here means monocypher's EdDSA output moved.
_PINNED_PK = "f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b"
_PINNED_SIG = (
    "e83009fa8880c1af370a90223796f87126697ead9176619c9f7a2d7bccd50b0f"
    "c167bb32a20e1061d80dd719b3f870470c6a452d1bc96505ed775e1885b72200"
)


# --------------------------------------------------------------- argon2id


def test_argon2id_matches_reference(tmp_path):
    """libtab embeds an argon2id digest in a HASHED cell using default
    params (m_log2=16 → 64 MiB, t=3, p=1, 16-byte salt). Decode the cell,
    recover the params + salt, recompute with argon2-cffi independently,
    and require an exact digest match."""
    pytest.importorskip("argon2")
    from argon2.low_level import Type, hash_secret_raw

    from libtab.native import NativeColumn, NativeTable

    preimage = b"correct horse battery staple"
    path = str(tmp_path / "t.tab")
    t = NativeTable.create(path, "t", [
        NativeColumn("id"),
        NativeColumn("pw", type="HASHED", algo="argon2id"),
    ])
    r = t.add_row("id", "a")
    t.set_hashed_argon2id(r, "pw", preimage)
    cell = t.get(r, "pw")
    t.close()

    # cell = "hashed:" + base64url(algo_id(1) m_log2(1) t(1) p(1) salt_len(1) salt digest(32))
    import base64

    wire = base64.urlsafe_b64decode(cell[len("hashed:"):])
    assert wire[0] == 0x02  # argon2id algo id
    m_log2, t_passes, p_lanes, salt_len = wire[1], wire[2], wire[3], wire[4]
    salt = wire[5:5 + salt_len]
    digest = wire[5 + salt_len:5 + salt_len + 32]

    ref = hash_secret_raw(
        secret=preimage,
        salt=salt,
        time_cost=t_passes,
        memory_cost=1 << m_log2,
        parallelism=p_lanes,
        hash_len=32,
        type=Type.ID,
    )
    assert digest == ref, "libtab argon2id digest disagrees with argon2-cffi reference"


# ------------------------------------------------ XChaCha20-Poly1305 (seal)
# The AEAD backing seal()/unseal(). A round-trip alone wouldn't catch a
# miscompiled cipher (it'd just be self-consistently wrong), so pin the
# exact ciphertext + MAC for a fixed key/nonce/plaintext.


def test_aead_pinned_vector(lib):
    key = bytes(range(32))
    nonce = bytes(range(24))
    pt = b"known answer test"

    ct = (ctypes.c_char * len(pt))()
    mac = (ctypes.c_char * 16)()
    kb = (ctypes.c_char * 32)(*[bytes([b]) for b in key])
    nb = (ctypes.c_char * 24)(*[bytes([b]) for b in nonce])
    lib.crypto_aead_lock(ct, mac, kb, nb, None, 0, pt, len(pt))

    assert bytes(ct)[: len(pt)].hex() == "f5ac6008fef2ecc0403343bceb26cd9b3f"
    assert bytes(mac).hex() == "4280110f1a04b633e45df510de820094"


def test_seal_unseal_are_inverse():
    """seal() then unseal() under the same key is the identity."""
    import os

    key = os.urandom(32)
    for pt in (b"", b"x", b"a longer secret value", os.urandom(300)):
        assert native.unseal(key, native.seal(key, pt)) == pt


def test_seal_ciphertext_does_not_contain_plaintext():
    """A distinctive multi-byte marker must not appear in the sealed blob.
    (Uses a long unique marker, not a single byte — a 1-byte plaintext can
    coincidentally appear in the 24-byte random nonce.)"""
    import os

    key = os.urandom(32)
    marker = b"UNIQUE-MARKER-9f3a1c-do-not-leak"
    blob = native.seal(key, marker)
    assert marker not in blob
