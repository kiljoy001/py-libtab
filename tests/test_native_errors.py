"""Error-path and accessor coverage for libtab/native.py.

The ctypes marshaling layer (argtypes/restype, buffer sizing, error
propagation from tab_lasterror) is Python-side logic on top of the real
C library, and it's exactly the kind of thing that can be subtly wrong
without any test noticing — a wrong argtype or an unchecked nil return
degrades to a segfault or silent data corruption, not a clean exception.
These tests exist to give mutation testing something to actually kill.
"""

from __future__ import annotations

import os

import pytest

native = pytest.importorskip("libtab.native")

if not os.path.exists(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")
):
    pytest.skip("vendor/libtab.so not built — run vendor/build.sh", allow_module_level=True)


def test_native_unavailable_when_so_missing(monkeypatch):
    monkeypatch.setattr(
        native.os.path, "exists", lambda p: False
    )
    with pytest.raises(native.NativeUnavailable):
        native._find_so()


def test_open_missing_file_raises(tmp_path):
    with pytest.raises(native.LibtabNativeError):
        native.NativeTable.open(str(tmp_path / "does_not_exist.tab"))


def test_open_malformed_file_raises(tmp_path):
    path = tmp_path / "bad.tab"
    path.write_text("this is not ndb-shaped schema data\n")
    with pytest.raises(native.LibtabNativeError):
        native.NativeTable.open(str(path))


def test_commit_to_missing_parent_dir_raises(tmp_path):
    # create() only builds the in-memory Tab; the filesystem write
    # happens at commit(). libtab.c's local-write path (tab_persist.c)
    # does NOT create missing parent directories — unlike a naive
    # implementation might assume, this must raise, not silently mkdir.
    t = native.NativeTable.create(
        str(tmp_path / "sub" / "orders.tab"), "orders", [native.NativeColumn("id")]
    )
    t.add_row("id", "a")
    with pytest.raises(native.LibtabNativeError):
        t.commit()
    t.close()


def test_set_unknown_column_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [native.NativeColumn("id")])
    r = t.add_row("id", "a")
    with pytest.raises(native.LibtabNativeError):
        t.set(r, "nosuchcolumn", "x")
    t.close()


def test_clear_cell(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("k"),
    ])
    r = t.add_row("id", "a")
    t.set(r, "k", "x")
    assert t.get(r, "k") == "x"
    t.clear(r, "k")
    assert t.get(r, "k") is None
    t.close()


def test_clear_unknown_column_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [native.NativeColumn("id")])
    r = t.add_row("id", "a")
    with pytest.raises(native.LibtabNativeError):
        t.clear(r, "nosuchcolumn")
    t.close()


def test_remove_row_twice_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [native.NativeColumn("id")])
    r = t.add_row("id", "a")
    t.remove_row(r)
    with pytest.raises(native.LibtabNativeError):
        t.remove_row(r)
    t.close()


def test_remove_row_drops_from_iteration(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [native.NativeColumn("id")])
    r1 = t.add_row("id", "a")
    t.add_row("id", "b")
    assert r1._freed is False
    t.remove_row(r1)
    assert r1._freed is True
    ids = {t.get(r, "id") for r in t.iter_rows()}
    assert ids == {"b"}
    t.close()


def test_context_manager_closes(tmp_path):
    path = str(tmp_path / "t.tab")
    with native.NativeTable.create(path, "t", [native.NativeColumn("id")]) as t:
        t.add_row("id", "a")
        t.commit()
        assert t._closed is False
    assert t._closed is True


def test_close_is_idempotent(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [native.NativeColumn("id")])
    t.add_row("id", "a")
    t.commit()
    t.close()
    t.close()  # must not raise or double-free


def test_schema_introspection(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"),
        native.NativeColumn("pwhash", type="HASHED", algo="argon2id"),
    ])
    assert t.ncolumns == 2
    assert t.colname(0) == "id"
    assert t.colname(1) == "pwhash"
    assert t.colname(99) is None
    assert t.coltype(0) is None
    assert t.coltype(1) == "HASHED"
    assert t.col_attr("pwhash", "algo") == "argon2id"
    assert t.col_attr("pwhash", "nosuchattr") is None
    assert t.col_attr("nosuchcol", "algo") is None
    t.close()


def test_get_missing_cell_returns_none(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("k"),
    ])
    r = t.add_row("id", "a")
    assert t.get(r, "k") is None
    t.close()


def test_search_no_matches_returns_empty(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("k"),
    ])
    t.add_row("id", "a")
    assert t.search("k", "nomatch") == []
    t.close()


def test_set_hashed_argon2id(tmp_path):
    pytest.importorskip("argon2")  # confirms C lib's argon2 support works too
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"),
        native.NativeColumn("pwhash", type="HASHED", algo="argon2id"),
    ])
    r = t.add_row("id", "a")
    t.set_hashed_argon2id(r, "pwhash", b"secret123")
    assert t.verify_hash(r, "pwhash", b"secret123") is True
    assert t.verify_hash(r, "pwhash", b"wrong") is False
    t.close()


def test_set_hashed_argon2id_wrong_column_type_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("plain"),
    ])
    r = t.add_row("id", "a")
    with pytest.raises(native.LibtabNativeError):
        t.set_hashed_argon2id(r, "plain", b"secret123")
    t.close()


def test_verify_hash_on_empty_cell_returns_false(tmp_path):
    """tab_verify_hash returns 0 (not -1) for an empty cell — the C
    library treats "nothing to compare against" as a non-match, not an
    error, even though it also calls tab_seterror internally. The
    NativeTable.verify_hash bool return only escalates rc < 0 to an
    exception, matching the C API's own success/failure boundary."""
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"),
        native.NativeColumn("pwhash", type="HASHED"),
    ])
    r = t.add_row("id", "a")  # pwhash never set — empty cell
    assert t.verify_hash(r, "pwhash", b"secret123") is False
    t.close()


def test_verify_hash_malformed_cell_raises(tmp_path):
    # typed columns reject pre-tagged text via the plain tab_set setter
    # (must go through tab_set_hashed), so write the malformed cell
    # directly at the file level and reopen.
    path = tmp_path / "t.tab"
    path.write_text(
        "schema=t\n\tcol=id\n\tcol=pwhash type=HASHED\n\n"
        "id=a\n\tpwhash=hashed:not-valid-base64!!!\n\n"
    )
    t = native.NativeTable.open(str(path))
    r = t.iter_rows()[0]
    with pytest.raises(native.LibtabNativeError):
        t.verify_hash(r, "pwhash", b"secret123")
    t.close()


def test_set_signed_wrong_column_type_raises(tmp_path):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("plain"),
    ])
    r = t.add_row("id", "a")
    sk, _pk = _monocypher_keypair(bytes(range(32)))
    with pytest.raises(native.LibtabNativeError):
        t.set_signed(r, "plain", b"hello", sk)
    t.close()


def test_set_hashed_wrong_column_type_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("plain"),
    ])
    r = t.add_row("id", "a")
    with pytest.raises(native.LibtabNativeError):
        t.set_hashed(r, "plain", b"secret123")
    t.close()


def test_set_signed_rejects_short_key(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")
    with pytest.raises(native.LibtabNativeError, match="64 bytes"):
        t.set_signed(r, "body", b"hello", b"short")
    t.close()


def test_verify_signed_rejects_short_key(tmp_path):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")
    sk, _pk = _monocypher_keypair(bytes(range(32)))
    t.set_signed(r, "body", b"hello", sk)
    with pytest.raises(native.LibtabNativeError, match="32 bytes"):
        t.verify_signed(r, "body", b"short")
    t.close()


def test_verify_signed_wrong_key_raises(tmp_path):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")
    sk, _pk = _monocypher_keypair(bytes(range(32)))
    _sk2, pk2 = _monocypher_keypair(bytes([9] * 32))
    t.set_signed(r, "body", b"hello", sk)
    with pytest.raises(native.LibtabNativeError):
        t.verify_signed(r, "body", pk2)
    t.close()


def test_b64_decode_invalid_input_raises():
    with pytest.raises(native.LibtabNativeError):
        native.b64_decode("not valid base64!!!")


def test_iter_rows_empty_table(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [native.NativeColumn("id")])
    assert t.iter_rows() == []
    t.close()
