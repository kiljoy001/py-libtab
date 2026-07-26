"""Assert the context prefix in every reachable _check_error failure.

_check_error raises `LibtabNativeError(f"{context}: {msg}")`. Mutation
testing tampered the `context` literal (e.g. "tab_set_signed" →
"XXtab_set_signedXX") at each call site and those survived, because the
existing failure-path tests only asserted that *something* raised, not
that the message carried the right context. Each test here triggers the
real C-level failure for one call site and asserts the message starts
with the correct context string.
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
Err = native.LibtabNativeError


def _assert_context(exc_info, context: str) -> None:
    assert str(exc_info.value).startswith(context + ":"), str(exc_info.value)


def test_open_context(tmp_path):
    with pytest.raises(Err) as ei:
        Tab.open(str(tmp_path / "nope.tab"))
    _assert_context(ei, "tab_open")


def test_set_context_typed_column(tmp_path):
    t = Tab.create(str(tmp_path / "t.tab"), "t", [Col("id"), Col("h", type="HASHED")])
    r = t.add_row("id", "a")
    with pytest.raises(Err) as ei:
        t.set(r, "h", "plaintext")  # typed cols reject plain tab_set
    _assert_context(ei, "tab_set")
    t.close()


def test_clear_context_unknown_column(tmp_path):
    t = Tab.create(str(tmp_path / "t.tab"), "t", [Col("id")])
    r = t.add_row("id", "a")
    with pytest.raises(Err) as ei:
        t.clear(r, "nosuchcol")
    _assert_context(ei, "tab_clear")
    t.close()


def test_commit_context_missing_parent_dir(tmp_path):
    t = Tab.create(str(tmp_path / "sub" / "x.tab"), "t", [Col("id")])
    t.add_row("id", "a")
    with pytest.raises(Err) as ei:
        t.commit()
    _assert_context(ei, "tab_commit")
    t.close()


def test_set_hashed_context_wrong_column_type(tmp_path):
    t = Tab.create(str(tmp_path / "t.tab"), "t", [Col("id"), Col("plain")])
    r = t.add_row("id", "a")
    with pytest.raises(Err) as ei:
        t.set_hashed(r, "plain", b"x")
    _assert_context(ei, "tab_set_hashed")
    t.close()


def test_set_hashed_argon2id_context_wrong_column_type(tmp_path):
    pytest.importorskip("argon2")
    t = Tab.create(str(tmp_path / "t.tab"), "t", [Col("id"), Col("plain")])
    r = t.add_row("id", "a")
    with pytest.raises(Err) as ei:
        t.set_hashed_argon2id(r, "plain", b"x")
    _assert_context(ei, "tab_set_hashed_argon2id")
    t.close()


def test_verify_hash_context_malformed_cell(tmp_path):
    path = tmp_path / "t.tab"
    path.write_text(
        "schema=t\n\tcol=id\n\tcol=pwhash type=HASHED\n\n"
        "id=a\n\tpwhash=hashed:not-valid-base64!!!\n\n"
    )
    t = Tab.open(str(path))
    r = t.iter_rows()[0]
    with pytest.raises(Err) as ei:
        t.verify_hash(r, "pwhash", b"x")
    _assert_context(ei, "tab_verify_hash")
    t.close()


def test_set_signed_context_wrong_column_type(tmp_path):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    t = Tab.create(str(tmp_path / "t.tab"), "t", [Col("id"), Col("plain")])
    r = t.add_row("id", "a")
    sk, _pk = _monocypher_keypair(bytes(range(32)))
    with pytest.raises(Err) as ei:
        t.set_signed(r, "plain", b"body", sk)
    _assert_context(ei, "tab_set_signed")
    t.close()


def test_verify_signed_context_wrong_key(tmp_path):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    t = Tab.create(str(tmp_path / "t.tab"), "t", [Col("id"), Col("body", type="SIGNED")])
    r = t.add_row("id", "a")
    sk, _pk = _monocypher_keypair(bytes(range(32)))
    _sk2, pk2 = _monocypher_keypair(bytes([9] * 32))
    t.set_signed(r, "body", b"hello", sk)
    with pytest.raises(Err) as ei:
        t.verify_signed(r, "body", pk2)
    _assert_context(ei, "tab_verify_signed")
    t.close()


def test_b64_decode_context_invalid_input():
    with pytest.raises(Err) as ei:
        native.b64_decode("!!!not-base64")
    _assert_context(ei, "tab_b64_decode")
