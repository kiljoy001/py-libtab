"""Isolated unit tests of the Python wrapper logic, with the C boundary
mocked.

Every *other* test in this suite drives the real libtab.so
(Tabula.create -> file -> open -> assert), so a failure there could be
the C library, ctypes marshaling, or the Python. These tests mock the
`lib.tab_*` calls entirely, so they exercise ONLY the Python layer we
wrote — the argument marshaling (.encode()), the `if rc:` success/error
decoding, get()'s None handling, _check_error propagation, and the
remove_row postcondition — and a failure fingers our Python, not the C
library or the filesystem. No .so and no disk are touched.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

native = pytest.importorskip("libtab.native")


@pytest.fixture
def fake_lib():
    """A mock C library. tab_lasterror returns b"no error" by default, so
    _check_error is a no-op unless a test says otherwise."""
    lib = MagicMock()
    lib.tab_lasterror.return_value = b"no error"
    return lib


@pytest.fixture
def table(fake_lib, monkeypatch):
    """A Tabula whose self._lib is the mock (Tabula.__init__ calls
    _get_lib, so we patch that), with a sentinel handle."""
    monkeypatch.setattr(native, "_get_lib", lambda: fake_lib)
    t = native.Tabula(handle=1234)   # opaque sentinel; never dereferenced
    return t


@pytest.fixture
def row():
    return native.Row(ptr=5678)


# ── set(): marshaling + success path ──────────────────────────────────

def test_set_marshals_and_succeeds(table, fake_lib, row):
    fake_lib.tab_set.return_value = 0          # 0 = success
    table.set(row, "col", "val")
    # Verify the Python encoded the strings and passed the handle/ptr.
    fake_lib.tab_set.assert_called_once_with(1234, 5678, b"col", b"val")
    # Success path must NOT consult the error channel.
    fake_lib.tab_lasterror.assert_not_called()


def test_set_nonzero_rc_raises_via_check_error(table, fake_lib, row):
    fake_lib.tab_set.return_value = -1         # -1 = error
    fake_lib.tab_lasterror.return_value = b"boom"
    with pytest.raises(native.TabulaError, match="tab_set: boom"):
        table.set(row, "col", "val")


def test_set_rc_zero_does_not_raise_even_if_lasterror_dirty(table, fake_lib, row):
    # The `if rc:` contract keys off the return code, not a stale error
    # string. rc==0 must succeed regardless of tab_lasterror.
    fake_lib.tab_set.return_value = 0
    fake_lib.tab_lasterror.return_value = b"stale error that must be ignored"
    table.set(row, "col", "val")               # must not raise


# ── get(): None decoding ──────────────────────────────────────────────

def test_get_decodes_bytes(table, fake_lib, row):
    fake_lib.tab_get.return_value = b"hello"
    assert table.get(row, "col") == "hello"
    fake_lib.tab_get.assert_called_once_with(5678, b"col")


def test_get_returns_none_for_missing(table, fake_lib, row):
    # tab_get returns nil (None) for a missing cell; the Python must map
    # that to None, not attempt b"".decode() on a None.
    fake_lib.tab_get.return_value = None
    assert table.get(row, "col") is None


# ── clear(): error branch ─────────────────────────────────────────────

def test_clear_success(table, fake_lib, row):
    fake_lib.tab_clear.return_value = 0
    table.clear(row, "col")
    fake_lib.tab_clear.assert_called_once_with(1234, 5678, b"col")


def test_clear_error_raises(table, fake_lib, row):
    fake_lib.tab_clear.return_value = -1
    fake_lib.tab_lasterror.return_value = b"nope"
    with pytest.raises(native.TabulaError, match="tab_clear: nope"):
        table.clear(row, "col")


# ── remove_row(): _freed postcondition ────────────────────────────────

def test_remove_row_sets_freed(table, fake_lib, row):
    fake_lib.tab_remove_row.return_value = 0
    assert row._freed is False
    table.remove_row(row)
    assert row._freed is True
    fake_lib.tab_remove_row.assert_called_once_with(1234, 5678)


def test_remove_row_error_raises_before_marking_freed(table, fake_lib, row):
    fake_lib.tab_remove_row.return_value = -1
    fake_lib.tab_lasterror.return_value = b"cannot remove"
    with pytest.raises(native.TabulaError, match="tab_remove_row: cannot remove"):
        table.remove_row(row)


# ── guards fire without touching the lib at all ───────────────────────

def test_set_on_closed_table_raises_without_calling_c(table, fake_lib, row):
    table._closed = True
    with pytest.raises(native.TabulaError):
        table.set(row, "c", "v")
    fake_lib.tab_set.assert_not_called()       # guard ran before the C call


def test_set_on_freed_row_raises_without_calling_c(table, fake_lib, row):
    row._freed = True
    with pytest.raises(native.TabulaError):
        table.set(row, "c", "v")
    fake_lib.tab_set.assert_not_called()


# ── add_row(): null-handle failure path ───────────────────────────────

def test_add_row_null_return_raises(table, fake_lib):
    # tab_add_row returns nil on failure; the Python must detect the
    # falsy handle and raise via _check_error rather than wrap None.
    fake_lib.tab_add_row.return_value = 0      # falsy = failure
    fake_lib.tab_lasterror.return_value = b"add failed"
    with pytest.raises(native.TabulaError, match="tab_add_row: add failed"):
        table.add_row("id", "x")


def test_add_row_success_wraps_pointer(table, fake_lib):
    fake_lib.tab_add_row.return_value = 999     # truthy pointer
    r = table.add_row("id", "x")
    assert isinstance(r, native.Row)
    assert r._ptr == 999
    fake_lib.tab_add_row.assert_called_once_with(1234, b"id", b"x")


# ── schema accessors: None decoding ───────────────────────────────────

def test_colname_decodes_and_none(table, fake_lib):
    fake_lib.tab_colname.return_value = b"payee"
    assert table.colname(0) == "payee"
    fake_lib.tab_colname.return_value = None
    assert table.colname(99) is None
