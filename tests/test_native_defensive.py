"""Covers the defensive fallback branches in native.py: what happens if
a C entry point returns a nil/failure handle but tab_lasterror() still
reports "no error" (a contract violation the C library shouldn't
normally produce, but the Python wrapper must not silently return a
broken handle if it somehow does).
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
def lib_with_faked_no_error(monkeypatch):
    """Patch tab_lasterror to always report "no error", so
    _check_error's own raise never fires and the fallback raise in each
    wrapper method is what has to catch the nil handle instead."""
    lib = native._get_lib()
    monkeypatch.setattr(lib, "tab_lasterror", lambda: b"no error")
    return lib


def test_create_fallback_raise_on_nil_handle_with_no_error(lib_with_faked_no_error, tmp_path, monkeypatch):
    monkeypatch.setattr(lib_with_faked_no_error, "tab_create", lambda *a: None)
    with pytest.raises(native.TabulaError, match="no error message"):
        native.Tabula.create(str(tmp_path / "t.tab"), "t", [native.Column("id")])


def test_open_fallback_raise_on_nil_handle_with_no_error(lib_with_faked_no_error, tmp_path, monkeypatch):
    monkeypatch.setattr(lib_with_faked_no_error, "tab_open", lambda *a: None)
    with pytest.raises(native.TabulaError, match="no error message"):
        native.Tabula.open(str(tmp_path / "t.tab"))


def test_add_row_fallback_raise_on_nil_handle_with_no_error(tmp_path, lib_with_faked_no_error, monkeypatch):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [native.Column("id")])
    monkeypatch.setattr(lib_with_faked_no_error, "tab_add_row", lambda *a: None)
    with pytest.raises(native.TabulaError, match="no error message"):
        t.add_row("id", "a")


def test_iter_fallback_raise_on_nil_iterator_with_no_error(tmp_path, lib_with_faked_no_error, monkeypatch):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [native.Column("id")])
    monkeypatch.setattr(lib_with_faked_no_error, "tab_iter", lambda *a: None)
    with pytest.raises(native.TabulaError, match="no error message"):
        t.iter_rows()


def test_search_fallback_raise_on_nil_iterator_with_no_error(tmp_path, lib_with_faked_no_error, monkeypatch):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [native.Column("id")])
    monkeypatch.setattr(lib_with_faked_no_error, "tab_search", lambda *a: None)
    with pytest.raises(native.TabulaError, match="no error message"):
        t.search("id", "a")


def test_b64_encode_fallback_raise_on_nil_with_no_error(lib_with_faked_no_error, monkeypatch):
    monkeypatch.setattr(lib_with_faked_no_error, "tab_b64_encode", lambda *a: None)
    with pytest.raises(native.TabulaError, match="no error message"):
        native.b64_encode(b"x")


def test_b64_decode_fallback_raise_on_nil_with_no_error(lib_with_faked_no_error, monkeypatch):
    monkeypatch.setattr(lib_with_faked_no_error, "tab_b64_decode", lambda *a, **k: None)
    with pytest.raises(native.TabulaError, match="no error message"):
        native.b64_decode("x")


def test_verify_signed_fallback_raise_on_nil_with_no_error(tmp_path, lib_with_faked_no_error, monkeypatch):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"), native.Column("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")
    sk, pk = _monocypher_keypair(bytes(range(32)))
    t.set_signed(r, "body", b"hello", sk)

    monkeypatch.setattr(lib_with_faked_no_error, "tab_verify_signed", lambda *a: None)
    with pytest.raises(native.TabulaError, match="no error message"):
        t.verify_signed(r, "body", pk)


def test_clear_and_remove_row_do_not_raise_on_success(tmp_path):
    """clear()/remove_row() call _check_error only when rc != 0 — this
    documents the success path explicitly (rc == 0 means no exception,
    not "swallow the check")."""
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"), native.Column("k"),
    ])
    r = t.add_row("id", "a")
    t.set(r, "k", "x")
    t.clear(r, "k")  # must not raise
    t.remove_row(r)  # must not raise
    t.close()
