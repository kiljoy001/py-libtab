"""Targeted tests closing the last behavioral mutation-survivor gaps.

Each test here kills a specific surviving mutant found by mutmut that the
broader suite missed. Grouped by the mutant class they target.
"""

from __future__ import annotations

import base64
import os

import pytest

native = pytest.importorskip("libtab.native")

if not os.path.exists(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")
):
    pytest.skip("vendor/libtab.so not built — run vendor/build.sh", allow_module_level=True)

Col = native.Column
Tab = native.Tabula


# --- create: column-spec fields (type/algo/signer) must reach _TabColSpec ---
# Kills create__mutmut_7/11 (dropping `c.signer.encode()`), and the
# analogous algo/type drops: if a field is not encoded into the spec, it
# won't appear in the persisted schema.


def test_create_encodes_all_column_spec_fields(tmp_path):
    path = str(tmp_path / "t.tab")
    t = Tab.create(path, "t", [
        Col("id"),
        Col("sig", type="SIGNED", signer="hostkey"),
        Col("pw", type="HASHED", algo="argon2id"),
    ])
    t.add_row("id", "a")
    t.commit()
    # type field
    assert t.coltype(1) == "SIGNED"
    assert t.coltype(2) == "HASHED"
    # signer field
    assert t.col_attr("sig", "signer") == "hostkey"
    # algo field
    assert t.col_attr("pw", "algo") == "argon2id"
    t.close()

    # and persisted across reopen
    t2 = Tab.open(path)
    assert t2.col_attr("sig", "signer") == "hostkey"
    assert t2.col_attr("pw", "algo") == "argon2id"
    assert t2.coltype(1) == "SIGNED"
    t2.close()


# --- _require_bytes: the wrong-type name in the message must be the
# actual value's type, not a constant. Kills _require_bytes__mutmut_3
# (`type(None).__name__` instead of `type(value).__name__`).


def test_require_bytes_message_names_actual_type():
    with pytest.raises(TypeError, match="got str"):
        native._require_bytes("a string", "arg")
    with pytest.raises(TypeError, match="got int"):
        native._require_bytes(123, "arg")
    with pytest.raises(TypeError, match="got list"):
        native._require_bytes([1], "arg")


# --- _get_lib must actually cache a real library, not None. Kills
# _get_lib__mutmut_2 (`_lib = None`).


def test_get_lib_returns_loaded_library():
    lib = native._get_lib()
    assert lib is not None
    # a bound function exists and is callable
    assert callable(lib.tab_b64_encode)
    # idempotent: second call returns the same cached object
    assert native._get_lib() is lib


def test_get_lib_populates_the_cache_from_none(monkeypatch):
    """Force the cache back to None so _get_lib's `_lib = _load()` branch
    actually runs — otherwise it's dead (the cache is populated at import
    time and the `if _lib is None` branch is never re-entered). Kills
    _get_lib__mutmut_2 (`_lib = None`), which is only observable on the
    populate-the-empty-cache path."""
    monkeypatch.setattr(native, "_lib", None)
    lib = native._get_lib()
    assert lib is not None
    assert callable(lib.tab_b64_encode)
    # the cache is now populated with the real library, not left as None
    assert native._lib is lib


# --- _string_at size argument is load-bearing: decoded bytes can contain
# an embedded NUL, and dropping the length would truncate at it. Kills
# b64_decode__mutmut_21 and verify_signed__mutmut_40 (`_string_at(ptr,)`).


def test_b64_decode_preserves_embedded_nul():
    raw = b"ab\x00cd"
    enc = base64.urlsafe_b64encode(raw).decode()
    assert native.b64_decode(enc) == raw  # 5 bytes, not truncated at the NUL


def test_verify_signed_preserves_embedded_nul(tmp_path):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    path = str(tmp_path / "t.tab")
    t = Tab.create(path, "t", [Col("id"), Col("body", type="SIGNED")])
    r = t.add_row("id", "a")
    sk, pk = _monocypher_keypair(bytes(range(32)))
    body = b"xy\x00zw"
    t.set_signed(r, "body", body, sk)
    assert t.verify_signed(r, "body", pk) == body  # embedded NUL survives
    t.close()


# --- unreachable-in-normal-use _check_error context strings: force the
# nil-return branch via monkeypatch so the context string on each such
# path is actually exercised and asserted. Kills the
# create/add_row/remove_row/iter_rows/search/b64_encode context mutants
# (_check_error(lib, None) / "XX...XX" / "UPPER").


@pytest.fixture
def force_error(monkeypatch):
    """Make tab_lasterror report a real error so _check_error raises,
    and let the caller stub a C function to return nil/nonzero."""
    lib = native._get_lib()
    monkeypatch.setattr(lib, "tab_lasterror", lambda: b"synthetic failure")
    return lib


def test_create_context_on_failure(force_error, monkeypatch, tmp_path):
    monkeypatch.setattr(force_error, "tab_create", lambda *a: None)
    with pytest.raises(native.TabulaError, match=r"^tab_create:"):
        Tab.create(str(tmp_path / "t.tab"), "t", [Col("id")])


def test_add_row_context_on_failure(force_error, monkeypatch, tmp_path):
    t = Tab.create(str(tmp_path / "t.tab"), "t", [Col("id")])
    monkeypatch.setattr(force_error, "tab_add_row", lambda *a: None)
    with pytest.raises(native.TabulaError, match=r"^tab_add_row:"):
        t.add_row("id", "a")


def test_iter_rows_context_on_failure(force_error, monkeypatch, tmp_path):
    t = Tab.create(str(tmp_path / "t.tab"), "t", [Col("id")])
    monkeypatch.setattr(force_error, "tab_iter", lambda *a: None)
    with pytest.raises(native.TabulaError, match=r"^tab_iter:"):
        t.iter_rows()


def test_search_context_on_failure(force_error, monkeypatch, tmp_path):
    t = Tab.create(str(tmp_path / "t.tab"), "t", [Col("id")])
    monkeypatch.setattr(force_error, "tab_search", lambda *a: None)
    with pytest.raises(native.TabulaError, match=r"^tab_search:"):
        t.search("id", "a")


def test_remove_row_context_on_failure(force_error, monkeypatch, tmp_path):
    t = Tab.create(str(tmp_path / "t.tab"), "t", [Col("id")])
    r = t.add_row("id", "a")
    monkeypatch.setattr(force_error, "tab_remove_row", lambda *a: -1)
    with pytest.raises(native.TabulaError, match=r"^tab_remove_row:"):
        t.remove_row(r)


def test_b64_encode_context_on_failure(force_error, monkeypatch):
    monkeypatch.setattr(force_error, "tab_b64_encode", lambda *a: None)
    with pytest.raises(native.TabulaError, match=r"^tab_b64_encode:"):
        native.b64_encode(b"x")
