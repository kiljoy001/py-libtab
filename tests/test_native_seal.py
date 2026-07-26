"""Tests for seal()/unseal() and the SEALED column convention.

Sealing is the confidentiality primitive: XChaCha20-Poly1305 (monocypher
AEAD) with a fresh random nonce per call, envelope nonce||mac||ciphertext
— byte-compatible with objective-9c's o9_encrypt. Unlike SIGNED (body in
the clear) and HASHED (irreversible), a sealed blob's plaintext cannot be
recovered without the key.
"""

from __future__ import annotations

import os

import pytest

native = pytest.importorskip("libtab.native")

if not os.path.exists(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")
):
    pytest.skip("vendor/libtab.so not built — run vendor/build.sh", allow_module_level=True)

Col = native.NativeColumn
Tab = native.NativeTable
KEY = bytes(range(32))


# ---- seal / unseal primitives ----


def test_seal_unseal_roundtrip():
    blob = native.seal(KEY, b"the secret")
    assert native.unseal(KEY, blob) == b"the secret"


def test_seal_hides_plaintext():
    blob = native.seal(KEY, b"PLAINTEXT-MARKER")
    assert b"PLAINTEXT-MARKER" not in blob
    assert b"PLAINTEXT" not in blob


def test_seal_envelope_layout():
    # nonce[24] || mac[16] || ciphertext(len == plaintext)
    pt = b"abcdef"
    blob = native.seal(KEY, pt)
    assert len(blob) == native.SEAL_NONCE_LEN + native.SEAL_MAC_LEN + len(pt)


def test_seal_fresh_nonce_each_call():
    # same key + plaintext must not produce identical blobs (random nonce)
    a = native.seal(KEY, b"x")
    b = native.seal(KEY, b"x")
    assert a != b
    assert native.unseal(KEY, a) == native.unseal(KEY, b) == b"x"


def test_unseal_wrong_key_raises():
    blob = native.seal(KEY, b"secret")
    with pytest.raises(native.LibtabNativeError, match="wrong key or tampered"):
        native.unseal(os.urandom(32), blob)


def test_unseal_tampered_blob_raises():
    blob = bytearray(native.seal(KEY, b"secret"))
    blob[-1] ^= 1  # flip a ciphertext bit
    with pytest.raises(native.LibtabNativeError, match="wrong key or tampered"):
        native.unseal(KEY, bytes(blob))


def test_unseal_tampered_nonce_raises():
    blob = bytearray(native.seal(KEY, b"secret"))
    blob[0] ^= 1  # flip a nonce bit
    with pytest.raises(native.LibtabNativeError):
        native.unseal(KEY, bytes(blob))


def test_seal_empty_plaintext():
    blob = native.seal(KEY, b"")
    assert native.unseal(KEY, blob) == b""


def test_seal_rejects_wrong_key_length():
    with pytest.raises(native.LibtabNativeError, match="32 bytes"):
        native.seal(b"short", b"x")


def test_unseal_rejects_wrong_key_length():
    blob = native.seal(KEY, b"x")
    with pytest.raises(native.LibtabNativeError, match="32 bytes"):
        native.unseal(b"short", blob)


def test_unseal_rejects_short_blob():
    with pytest.raises(native.LibtabNativeError, match="too short"):
        native.unseal(KEY, b"tiny")


def test_seal_rejects_non_bytes():
    with pytest.raises(TypeError, match="key must be bytes"):
        native.seal("not bytes", b"x")
    with pytest.raises(TypeError, match="plaintext must be bytes"):
        native.seal(KEY, "not bytes")


def test_unseal_rejects_non_bytes():
    # message must name the actual argument ("key" / "blob"), killing the
    # _require_bytes name-arg mutants
    with pytest.raises(TypeError, match="key must be bytes"):
        native.unseal("not bytes", b"x" * 40)
    with pytest.raises(TypeError, match="blob must be bytes"):
        native.unseal(KEY, "not bytes")


def test_seal_o9_envelope_compatibility():
    """A py-sealed blob must parse under o9_decrypt's exact split:
    nonce=blob[0:24], mac=blob[24:40], ct=blob[40:], then aead_unlock —
    proving byte-compatibility with objective-9c secret fields."""
    import ctypes

    lib = native._get_lib()
    blob = native.seal(KEY, b"interop")
    nonce, mac, ct = blob[0:24], blob[24:40], blob[40:]
    pt = (ctypes.c_char * len(ct))()
    kb = (ctypes.c_char * 32)(*[bytes([b]) for b in KEY])
    nb = (ctypes.c_char * 24)(*[bytes([b]) for b in nonce])
    mb = (ctypes.c_char * 16)(*[bytes([b]) for b in mac])
    rc = lib.crypto_aead_unlock(pt, mb, kb, nb, None, 0, ct, len(ct))
    assert rc == 0
    assert bytes(pt)[: len(ct)] == b"interop"


# ---- SEALED column convention ----


def test_set_get_sealed_roundtrip(tmp_path):
    path = str(tmp_path / "t.tab")
    t = Tab.create(path, "t", [Col("id"), Col("secret")])
    r = t.add_row("id", "a")
    t.set_sealed(r, "secret", b"sk-live-xyz", KEY)
    assert t.get_sealed(r, "secret", KEY) == b"sk-live-xyz"
    t.close()


def test_sealed_cell_is_inert_text(tmp_path):
    path = tmp_path / "t.tab"
    t = Tab.create(str(path), "t", [Col("id"), Col("secret")])
    r = t.add_row("id", "a")
    t.set_sealed(r, "secret", b"top-secret-value", KEY)
    t.commit()
    t.close()
    raw = path.read_bytes()
    assert b"top-secret-value" not in raw       # plaintext never on disk
    assert b"secret=sealed:" in raw             # stored as a tagged blob


def test_sealed_column_survives_reopen(tmp_path):
    path = str(tmp_path / "t.tab")
    t = Tab.create(path, "t", [Col("id"), Col("secret")])
    r = t.add_row("id", "a")
    t.set_sealed(r, "secret", b"persisted", KEY)
    t.commit()
    t.close()

    # file is valid stock libtab (plain column) — reopens fine
    t2 = Tab.open(path)
    r2 = t2.search("id", "a")[0]
    assert t2.get_sealed(r2, "secret", KEY) == b"persisted"
    t2.close()


def test_get_sealed_wrong_key_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = Tab.create(path, "t", [Col("id"), Col("secret")])
    r = t.add_row("id", "a")
    t.set_sealed(r, "secret", b"secret", KEY)
    with pytest.raises(native.LibtabNativeError, match="wrong key or tampered"):
        t.get_sealed(r, "secret", os.urandom(32))
    t.close()


def test_get_sealed_on_unsealed_cell_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = Tab.create(path, "t", [Col("id"), Col("plain")])
    r = t.add_row("id", "a")
    t.set(r, "plain", "just text")
    with pytest.raises(native.LibtabNativeError, match="not a sealed value"):
        t.get_sealed(r, "plain", KEY)
    t.close()


def test_get_sealed_on_missing_cell_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = Tab.create(path, "t", [Col("id"), Col("secret")])
    r = t.add_row("id", "a")  # secret never set
    with pytest.raises(native.LibtabNativeError, match="not a sealed value"):
        t.get_sealed(r, "secret", KEY)
    t.close()
