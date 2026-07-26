"""Tests for the ctypes-backed native engine (libtab/native.py).

Skips entirely if vendor/libtab.so hasn't been built (run vendor/build.sh),
since the native engine is an optional, separately-built C backend, not
part of the pure-Python install.
"""

from __future__ import annotations

import os

import pytest

native = pytest.importorskip("libtab.native")

if not os.path.exists(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")
):
    pytest.skip("vendor/libtab.so not built — run vendor/build.sh", allow_module_level=True)


def test_create_add_commit_reopen(tmp_path):
    path = str(tmp_path / "orders.tab")
    t = native.NativeTable.create(path, "orders", [
        native.NativeColumn("id"),
        native.NativeColumn("item"),
        native.NativeColumn("qty"),
        native.NativeColumn("status"),
    ])
    r = t.add_row("id", "a")
    t.set(r, "item", "widget")
    t.set(r, "qty", "5")
    t.set(r, "status", "paid")
    t.commit()
    t.close()

    t2 = native.NativeTable.open(path)
    assert t2.schema_name == "orders"
    assert t2.ncolumns == 4
    rows = t2.iter_rows()
    assert len(rows) == 1
    assert t2.get(rows[0], "item") == "widget"
    t2.close()


def test_search(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"), native.NativeColumn("k"),
    ])
    for rid, k in [("a", "x"), ("b", "y"), ("c", "x")]:
        r = t.add_row("id", rid)
        t.set(r, "k", k)

    results = t.search("k", "x")
    ids = {t.get(r, "id") for r in results}
    assert ids == {"a", "c"}
    t.close()


def test_serialized_output_shape(tmp_path):
    path = str(tmp_path / "orders.tab")
    nt = native.NativeTable.create(path, "orders", [
        native.NativeColumn("id"), native.NativeColumn("item"),
    ])
    r = nt.add_row("id", "a")
    nt.set(r, "item", "widget")
    nt.commit()
    nt.close()

    with open(path) as f:
        text = f.read()
    assert text.startswith("schema=orders\n")
    assert "\tcol=id\n" in text
    assert "id=a\n" in text
    assert "\titem=widget\n" in text


def test_hashed_blake2b_roundtrip(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"),
        native.NativeColumn("pwhash", type="HASHED"),
    ])
    r = t.add_row("id", "a")
    t.set_hashed(r, "pwhash", b"secret123")
    assert t.verify_hash(r, "pwhash", b"secret123") is True
    assert t.verify_hash(r, "pwhash", b"wrong") is False
    t.close()


# Single source of truth lives in tests/conftest.py; re-exported here
# under the historical name so existing call sites keep working.
from tests.conftest import monocypher_keypair as _monocypher_keypair


def test_signed_roundtrip(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.NativeTable.create(path, "t", [
        native.NativeColumn("id"),
        native.NativeColumn("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")

    seed = bytes(range(32))
    combined_sk, pk_bytes = _monocypher_keypair(seed)

    t.set_signed(r, "body", b"hello world", combined_sk)
    body = t.verify_signed(r, "body", pk_bytes)
    assert body == b"hello world"
    t.close()


def test_b64_roundtrip():
    data = b"hello world"
    encoded = native.b64_encode(data)
    assert encoded == "aGVsbG8gd29ybGQ="
    assert native.b64_decode(encoded) == data
