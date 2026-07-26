"""Tests for NativeTable._check_open — using a table after close().

Found via mutation testing + manual reproduction: tab_close() frees the
underlying C Tab struct, but nothing on the Python side previously
checked for this. Calling a method after close() did not reliably
raise or crash — it could silently return garbage read from freed or
reused memory (observed directly: colname(0) returned an unrelated
character instead of erroring). Every NativeTable method that touches
self._handle must check _closed first and raise cleanly.
"""

from __future__ import annotations

import os

import pytest

native = pytest.importorskip("libtab.native")

if not os.path.exists(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")
):
    pytest.skip("vendor/libtab.so not built — run vendor/build.sh", allow_module_level=True)


@pytest.fixture
def closed_table(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("k"),
    ])
    t.add_row("id", "a")
    t.commit()
    t.close()
    return t


def test_add_row_after_close_raises(closed_table):
    with pytest.raises(native.LibtabNativeError, match="closed"):
        closed_table.add_row("id", "b")


def test_commit_after_close_raises(closed_table):
    with pytest.raises(native.LibtabNativeError, match="closed"):
        closed_table.commit()


def test_schema_name_after_close_raises(closed_table):
    with pytest.raises(native.LibtabNativeError, match="closed"):
        _ = closed_table.schema_name


def test_ncolumns_after_close_raises(closed_table):
    with pytest.raises(native.LibtabNativeError, match="closed"):
        _ = closed_table.ncolumns


def test_colname_after_close_raises(closed_table):
    with pytest.raises(native.LibtabNativeError, match="closed"):
        closed_table.colname(0)


def test_coltype_after_close_raises(closed_table):
    with pytest.raises(native.LibtabNativeError, match="closed"):
        closed_table.coltype(0)


def test_col_attr_after_close_raises(closed_table):
    with pytest.raises(native.LibtabNativeError, match="closed"):
        closed_table.col_attr("k", "algo")


def test_iter_rows_after_close_raises(closed_table):
    with pytest.raises(native.LibtabNativeError, match="closed"):
        closed_table.iter_rows()


def test_search_after_close_raises(closed_table):
    with pytest.raises(native.LibtabNativeError, match="closed"):
        closed_table.search("k", "x")


def test_set_hashed_after_close_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("pwhash", type="HASHED"),
    ])
    r = t.add_row("id", "a")
    t.commit()
    t.close()
    with pytest.raises(native.LibtabNativeError, match="closed"):
        t.set_hashed(r, "pwhash", b"secret123")


def test_set_hashed_argon2id_after_close_raises(tmp_path):
    pytest.importorskip("argon2")
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"),
        native.NativeColumn("pwhash", type="HASHED", algo="argon2id"),
    ])
    r = t.add_row("id", "a")
    t.commit()
    t.close()
    with pytest.raises(native.LibtabNativeError, match="closed"):
        t.set_hashed_argon2id(r, "pwhash", b"secret123")


def test_set_signed_after_close_raises(tmp_path):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")
    t.commit()
    t.close()
    sk, _pk = _monocypher_keypair(bytes(range(32)))
    with pytest.raises(native.LibtabNativeError, match="closed"):
        t.set_signed(r, "body", b"hello", sk)


def test_set_and_clear_after_close_raise(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("k"),
    ])
    r = t.add_row("id", "a")
    t.commit()
    t.close()
    with pytest.raises(native.LibtabNativeError, match="closed"):
        t.set(r, "k", "x")
    with pytest.raises(native.LibtabNativeError, match="closed"):
        t.get(r, "k")
    with pytest.raises(native.LibtabNativeError, match="closed"):
        t.clear(r, "k")


def test_remove_row_after_close_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [native.NativeColumn("id")])
    r = t.add_row("id", "a")
    t.commit()
    t.close()
    with pytest.raises(native.LibtabNativeError, match="closed"):
        t.remove_row(r)


def test_double_close_still_idempotent(closed_table):
    closed_table.close()  # must not raise
