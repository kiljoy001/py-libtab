"""Subprocess smoke tests. The `aaa` in the filename is deliberate: it
makes this file collect before every test_native*.py file, so under
`pytest -x` (mutmut's runner) these run FIRST.

Why subprocess: libtab.c trusts its caller completely — a mutant that
disables one of the Python-side safety guards makes the first in-process
test touching that path die by SIGSEGV, killing the whole pytest run
before any cleanly-failing assertion elsewhere gets a chance to report.
Running the crash-prone flows in a child process first converts "the
process died" into an ordinary parent-side assertion failure on the
child's returncode: a mutant that would segfault now gets recorded by
mutation testing as killed, not as a crash that masks the rest of the
run.

The child inherits os.environ (including MUTANT_UNDER_TEST, so under
mutmut it exercises the mutated code) and gets PYTHONPATH pointed at
whichever copy of the package the parent imported — the mutants/ tree
under mutmut, the real tree otherwise.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

native = pytest.importorskip("libtab.native")

if not os.path.exists(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")
):
    pytest.skip("vendor/libtab.so not built — run vendor/build.sh", allow_module_level=True)

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(native.__file__)))


def _run_child(script: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = _PKG_ROOT
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        cwd=_PKG_ROOT,
        check=False,  # we assert on returncode ourselves (a segfault = -11)
    )


def _assert_clean_exit(proc: subprocess.CompletedProcess) -> None:
    assert proc.returncode >= 0, (
        f"child died by signal {-proc.returncode} (SIGSEGV is 11) — a "
        f"safety guard has been disabled\nstdout: {proc.stdout}\n"
        f"stderr: {proc.stderr}"
    )
    assert proc.returncode == 0, (
        f"child exited {proc.returncode}\nstdout: {proc.stdout}\n"
        f"stderr: {proc.stderr}"
    )


def test_happy_paths_survive_in_subprocess():
    """b64 roundtrip, SIGNED roundtrip, create/commit/reopen — the flows
    whose final raw-memory reads (ctypes.string_at) or out-parameter
    writes would crash if their guards or call sites were corrupted."""
    script = r"""
import ctypes, os, tempfile
from libtab import native

# b64 roundtrip
enc = native.b64_encode(b"hello world")
assert enc == "aGVsbG8gd29ybGQ=", enc
assert native.b64_decode(enc) == b"hello world"

# SIGNED roundtrip with a monocypher-derived keypair
lib = native._get_lib()
lib.crypto_eddsa_key_pair.restype = None
lib.crypto_eddsa_key_pair.argtypes = [
    ctypes.c_char * 64, ctypes.c_char * 32, ctypes.c_char * 32,
]
sk_buf = (ctypes.c_char * 64)()
pk_buf = (ctypes.c_char * 32)()
seed_buf = (ctypes.c_char * 32)(*[bytes([b]) for b in range(32)])
lib.crypto_eddsa_key_pair(sk_buf, pk_buf, seed_buf)

with tempfile.TemporaryDirectory() as d:
    path = os.path.join(d, "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"),
        native.Column("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")
    t.set_signed(r, "body", b"hello", bytes(sk_buf))
    assert t.verify_signed(r, "body", bytes(pk_buf)) == b"hello"
    t.commit()
    t.close()

    t2 = native.Tabula.open(path)
    assert t2.schema_name == "t"
    rows = t2.iter_rows()
    assert len(rows) == 1
    t2.close()
"""
    _assert_clean_exit(_run_child(script))


def test_guard_probes_survive_in_subprocess():
    """Deliberately lethal inputs against every guard. With guards
    intact each raises cleanly and the child exits 0; with a guard
    mutated away the child segfaults and the parent fails on the
    negative returncode."""
    script = r"""
from libtab import native

# _string_at address plausibility
for bad in (None, 0, 11, 4095, "notanint"):
    try:
        native._string_at(bad)
        raise SystemExit(f"_string_at({bad!r}) did not raise")
    except native.TabulaError:
        pass

# non-null argtype guards, exercised through real C entry points
lib = native._get_lib()
import ctypes as _ct
_mac = (_ct.c_char * 16)(); _key = (_ct.c_char * 32)(); _nonce = (_ct.c_char * 24)()
_buf = (_ct.c_char * 4)()
for fn, args in [
    (lib.tab_b64_encode, (None, 5)),
    (lib.tab_b64_decode, (b"aGVsbG8=", None)),
    (lib.tab_colname, (None, 0)),
    (lib.tab_coltype, (None, 0)),
    (lib.tab_commit, (None,)),
    (lib.tab_close, (None,)),
    # AEAD: null output buffer (arg 0) and null input (arg 6) must be
    # rejected, not segfault the cipher
    (lib.crypto_aead_lock, (None, _mac, _key, _nonce, None, 0, b"x", 1)),
    (lib.crypto_aead_lock, (_buf, _mac, _key, _nonce, None, 0, None, 1)),
    (lib.crypto_aead_unlock, (None, _mac, _key, _nonce, None, 0, b"x", 1)),
    (lib.crypto_aead_unlock, (_buf, _mac, _key, _nonce, None, 0, None, 1)),
]:
    try:
        fn(*args)
        raise SystemExit(f"{fn} accepted a null argument")
    except Exception as e:
        if isinstance(e, SystemExit):
            raise

# closed-table guard: garbage-read prevention after tab_close
import os, tempfile
with tempfile.TemporaryDirectory() as d:
    path = os.path.join(d, "t.tab")
    t = native.Tabula.create(path, "t", [native.Column("id")])
    t.add_row("id", "a")
    t.commit()
    t.close()
    assert t._closed is True
    try:
        t.colname(0)
        raise SystemExit("closed-table access did not raise")
    except native.TabulaError:
        pass

# freed-row guard: use-after-free prevention after remove_row
with tempfile.TemporaryDirectory() as d:
    path = os.path.join(d, "t.tab")
    t = native.Tabula.create(path, "t", [native.Column("id")])
    r = t.add_row("id", "a")
    t.remove_row(r)
    assert r._freed is True
    try:
        t.get(r, "id")
        raise SystemExit("freed-row access did not raise")
    except native.TabulaError:
        pass
    t.close()
"""
    _assert_clean_exit(_run_child(script))
