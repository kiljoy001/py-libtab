"""Tests for _require_bytes and its call sites.

Found via mutation testing: a mutant that passed None in place of a
bytes buffer to tab_b64_encode, while len() was still computed against
the original (unmutated) buffer, segfaulted the whole Python process
instead of raising — because libtab.c does no bounds/null checking of
its own on (pointer, length) arguments. _require_bytes closes this by
validating every raw-bytes buffer before it reaches a ctypes FFI call
that pairs it with a separately-computed length.
"""

from __future__ import annotations

import os

import pytest

native = pytest.importorskip("libtab.native")

if not os.path.exists(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")
):
    pytest.skip("vendor/libtab.so not built — run vendor/build.sh", allow_module_level=True)


def test_require_bytes_accepts_bytes():
    assert native._require_bytes(b"x", "arg") == b"x"


@pytest.mark.parametrize("bad", [None, "a string", 123, [1, 2, 3], bytearray(b"x")])
def test_require_bytes_rejects_non_bytes(bad):
    with pytest.raises(TypeError, match="must be bytes"):
        native._require_bytes(bad, "arg")


def test_b64_encode_rejects_non_bytes():
    with pytest.raises(TypeError):
        native.b64_encode(None)
    with pytest.raises(TypeError):
        native.b64_encode("not bytes")


# Every test below asserts the parameter NAME in the raised TypeError,
# not just that TypeError was raised. This kills the `_require_bytes(x,
# None)` mutants at each call site: with the name arg nulled, the message
# reads "None must be bytes" instead of "<name> must be bytes", so a
# `match=<name>` assertion fails.


def test_set_hashed_rejects_non_bytes_preimage(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("pwhash", type="HASHED"),
    ])
    r = t.add_row("id", "a")
    with pytest.raises(TypeError, match="preimage must be bytes"):
        t.set_hashed(r, "pwhash", "not bytes")
    t.close()


def test_set_hashed_argon2id_rejects_non_bytes_preimage(tmp_path):
    pytest.importorskip("argon2")
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"),
        native.NativeColumn("pwhash", type="HASHED", algo="argon2id"),
    ])
    r = t.add_row("id", "a")
    with pytest.raises(TypeError, match="preimage must be bytes"):
        t.set_hashed_argon2id(r, "pwhash", "not bytes")
    t.close()


def test_verify_hash_rejects_non_bytes_preimage(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("pwhash", type="HASHED"),
    ])
    r = t.add_row("id", "a")
    t.set_hashed(r, "pwhash", b"secret123")
    with pytest.raises(TypeError, match="preimage must be bytes"):
        t.verify_hash(r, "pwhash", "not bytes")
    t.close()


def test_set_signed_rejects_non_bytes_body(tmp_path):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")
    sk, _pk = _monocypher_keypair(bytes(range(32)))
    with pytest.raises(TypeError, match="body must be bytes"):
        t.set_signed(r, "body", "not bytes", sk)
    t.close()


def test_set_signed_rejects_non_bytes_signer_sk(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")
    with pytest.raises(TypeError, match="signer_sk must be bytes"):
        t.set_signed(r, "body", b"hello", "not bytes")
    t.close()


def test_verify_signed_rejects_non_bytes_signer_pk(tmp_path):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")
    sk, _pk = _monocypher_keypair(bytes(range(32)))
    t.set_signed(r, "body", b"hello", sk)
    with pytest.raises(TypeError, match="signer_pk must be bytes"):
        t.verify_signed(r, "body", "not bytes")
    t.close()


def test_b64_encode_rejects_non_bytes_with_name(tmp_path):
    with pytest.raises(TypeError, match="data must be bytes"):
        native.b64_encode("not bytes")
