"""Tests for _NonNullHandle/_NonNullCharP/_NonNullIntP and _string_at —
the guards that reject bad values at the FFI dispatch boundary.

Why argtype guards, not Python-side assertions: mutation testing found
that a mutant which replaced `self._handle` with a literal `None`
directly inside a ctypes call (e.g. `tab_colname(None, idx)`) could not
be caught by any assertion checking `self._handle` itself, because the
mutation bypasses that variable entirely at the call site — the
assertion and the mutated expression are different pieces of syntax.
ctypes calls from_param() on every argument whose argtype is set,
before the actual C call executes, which is a check that runs
regardless of what expression constructed the argument.

Deliberately NOT here: probes that feed lethal values (None, address 0)
through the full C path in-process. Under a mutant that disables a
guard, such a probe segfaults the test process, killing the run before
any cleanly-failing test can report. Those probes live in
tests/test_aaa_subprocess_smoke.py, where a crash is contained in a
child process and surfaces as a clean returncode assertion. Everything
in THIS file is safe to execute under any single mutation of the guard
code: direct from_param calls never reach C (they raise or return a
conversion object), and _string_at is only fed valid addresses.
"""

from __future__ import annotations

import os

import pytest

native = pytest.importorskip("libtab.native")

if not os.path.exists(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")
):
    pytest.skip("vendor/libtab.so not built — run vendor/build.sh", allow_module_level=True)


def test_nonnull_handle_accepts_real_pointer():
    assert native._NonNullHandle.from_param(12345) is not None


def test_nonnull_handle_rejects_none():
    with pytest.raises(native.TabulaError, match="null handle"):
        native._NonNullHandle.from_param(None)


def test_nonnull_charp_rejects_none():
    with pytest.raises(native.TabulaError, match="null string"):
        native._NonNullCharP.from_param(None)


def test_nonnull_charp_accepts_bytes():
    assert native._NonNullCharP.from_param(b"x") is not None


def test_nonnull_intp_rejects_none():
    with pytest.raises(native.TabulaError, match="out-parameter"):
        native._NonNullIntP.from_param(None)


def test_nonnull_intp_accepts_byref():
    import ctypes

    outlen = ctypes.c_int(0)
    assert native._NonNullIntP.from_param(ctypes.byref(outlen)) is not None


def test_string_at_reads_real_memory():
    import ctypes

    buf = ctypes.create_string_buffer(b"hello")
    addr = ctypes.addressof(buf)
    assert native._string_at(addr) == b"hello"
    assert native._string_at(addr, 5) == b"hello"
    assert native._string_at(addr, 0) == b""


def test_address_is_plausible_predicate():
    # pure-logic probes of the guard's decision function — no memory
    # access here, so a mutant of the predicate dies as a clean
    # assertion failure instead of reaching ctypes.string_at
    assert native._address_is_plausible(None) is False
    assert native._address_is_plausible("x") is False
    assert native._address_is_plausible(0) is False
    assert native._address_is_plausible(11) is False
    assert native._address_is_plausible(native._MIN_PLAUSIBLE_ADDR - 1) is False
    assert native._address_is_plausible(native._MIN_PLAUSIBLE_ADDR) is True
    assert native._address_is_plausible(native._MIN_PLAUSIBLE_ADDR + 1) is True
