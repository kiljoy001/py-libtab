"""Assert the exact ctypes signature (restype + argtypes) of every libtab
C function the wrapper binds.

Why: mutation testing found that _load() is almost entirely unchecked —
mutants that set an `argtypes`/`restype` to None, `""`, or tamper a
buffer size (`c_char * 64` → `* 65`) all survived, because no test ever
inspected the loaded signatures. A nulled `argtypes` silently disables
the _NonNullHandle / _NonNullCharP / _NonNullIntP guards (turning a
clean rejection back into a potential segfault), and a wrong restype
corrupts how return values are marshaled. This test pins every signature
so any such mutation fails.

The expected table is written out in full rather than derived from
_load(), so it is an independent statement of intent: if _load() drifts,
this test catches it instead of rubber-stamping whatever _load() happens
to produce.
"""

from __future__ import annotations

import ctypes
import os

import pytest

native = pytest.importorskip("libtab.native")

if not os.path.exists(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")
):
    pytest.skip("vendor/libtab.so not built — run vendor/build.sh", allow_module_level=True)

c_char_p = ctypes.c_char_p
c_int = ctypes.c_int
c_void_p = ctypes.c_void_p
H = native._NonNullHandle
CP = native._NonNullCharP
IP = native._NonNullIntP
COLSPEC_P = ctypes.POINTER(native._TabColSpec)
SK64 = ctypes.c_char * 64
PK32 = ctypes.c_char * 32
MAC16 = ctypes.c_char * 16
NONCE24 = ctypes.c_char * 24
KEY32 = ctypes.c_char * 32
c_size_t = ctypes.c_size_t

# name -> (restype, [argtypes])
EXPECTED = {
    "tab_create": (c_void_p, [c_char_p, c_char_p, COLSPEC_P, c_int]),
    "tab_add_row": (c_void_p, [H, c_char_p, c_char_p]),
    "tab_set": (c_int, [H, H, c_char_p, c_char_p]),
    "tab_clear": (c_int, [H, H, c_char_p]),
    "tab_remove_row": (c_int, [H, H]),
    "tab_open": (c_void_p, [c_char_p]),
    "tab_close": (None, [H]),
    "tab_commit": (c_int, [H]),
    "tab_lasterror": (c_char_p, []),
    "tab_schema_name": (c_char_p, [H]),
    "tab_ncolumns": (c_int, [H]),
    "tab_colname": (c_char_p, [H, c_int]),
    "tab_coltype": (c_char_p, [H, c_int]),
    "tab_col_attr": (c_char_p, [H, c_char_p, c_char_p]),
    "tab_iter": (c_void_p, [H]),
    "tab_search": (c_void_p, [H, c_char_p, c_char_p]),
    "tab_iter_next": (c_void_p, [H]),
    "tab_iter_close": (None, [H]),
    "tab_get": (c_char_p, [H, c_char_p]),
    "tab_b64_encode": (c_void_p, [CP, c_int]),
    "tab_b64_decode": (c_void_p, [CP, IP]),
    "tab_set_hashed": (c_int, [H, H, c_char_p, c_char_p, c_int]),
    "tab_set_hashed_argon2id": (c_int, [H, H, c_char_p, c_char_p, c_int]),
    "tab_verify_hash": (c_int, [H, c_char_p, c_char_p, c_int]),
    "tab_set_signed": (c_int, [H, H, c_char_p, c_char_p, c_int, SK64]),
    "tab_verify_signed": (c_void_p, [H, c_char_p, PK32, IP]),
    # monocypher AEAD, used by seal()/unseal(). Output buf (arg 0) and
    # plaintext/ciphertext input (arg 6) are guarded non-null; `ad`
    # (arg 4) stays plain c_char_p (called with None for no additional data).
    "crypto_aead_lock": (
        None, [CP, MAC16, KEY32, NONCE24, c_char_p, c_size_t, CP, c_size_t],
    ),
    "crypto_aead_unlock": (
        c_int, [CP, MAC16, KEY32, NONCE24, c_char_p, c_size_t, CP, c_size_t],
    ),
}


@pytest.fixture
def lib():
    # Function-scoped (NOT module-scoped) and calls _load() directly, not
    # _get_lib(): under mutation testing, mutmut associates a mutant with
    # only the tests whose *own execution* ran the mutated code. _load()
    # must therefore run inside every test that asserts a signature, so
    # each test independently covers every argtypes/restype line — a
    # module-scoped fixture would run _load once and associate it with a
    # single test, leaving the rest of _load's mutants effectively
    # untested. _get_lib() would be worse still (cached at import time).
    return native._load()


@pytest.mark.parametrize("fname", sorted(EXPECTED))
def test_restype(lib, fname):
    want_restype, _ = EXPECTED[fname]
    fn = getattr(lib, fname)
    assert fn.restype is want_restype, (
        f"{fname}.restype is {fn.restype!r}, expected {want_restype!r}"
    )


@pytest.mark.parametrize("fname", sorted(EXPECTED))
def test_argtypes(lib, fname):
    _, want_argtypes = EXPECTED[fname]
    fn = getattr(lib, fname)
    got = list(fn.argtypes) if fn.argtypes is not None else None
    assert got == want_argtypes, (
        f"{fname}.argtypes is {got!r}, expected {want_argtypes!r}"
    )


def test_guarded_pointer_args_use_nonnull_types(lib):
    """A plain c_void_p / c_char_p / POINTER(c_int) where a _NonNull*
    guard belongs would re-open the segfault door. Assert that every
    argument we intended to guard is in fact one of the guard types —
    catches a mutant that swaps a guarded argtype back to the plain one
    even if the count/shape is otherwise unchanged."""
    guarded = {H, CP, IP}
    for fname, (_, want_argtypes) in EXPECTED.items():
        fn = getattr(lib, fname)
        got = list(fn.argtypes) if fn.argtypes is not None else []
        for i, want in enumerate(want_argtypes):
            if want in guarded:
                assert got[i] is want, (
                    f"{fname} arg {i} must be the guard type {want.__name__}, "
                    f"got {got[i]!r}"
                )


def test_every_bound_function_has_argtypes_set(lib):
    """No wrapper-called binding may ship with argtypes left at the
    ctypes default (None) — that silently disables all argument
    conversion and guards. tab_lasterror is the only zero-arg function;
    its argtypes is the empty list [], which is explicitly set (not
    None)."""
    for fname in EXPECTED:
        fn = getattr(lib, fname)
        assert fn.argtypes is not None, f"{fname}.argtypes was left as None"


def test_find_so_returns_the_vendor_path(tmp_path):
    """Kills the _find_so path-component mutants (drop 'vendor', drop
    'libtab.so', drop 'here'): the resolved path must end in exactly
    vendor/libtab.so and must be the real file."""
    path = native._find_so()
    assert path.endswith(os.path.join("vendor", "libtab.so")), path
    assert os.path.isfile(path), path
    # 'here' is the package parent; dropping it would yield a relative or
    # wrong-rooted path. Assert it is absolute and rooted at the repo.
    assert os.path.isabs(path), path
    expected_root = os.path.dirname(os.path.dirname(os.path.abspath(native.__file__)))
    assert path == os.path.join(expected_root, "vendor", "libtab.so"), path


def test_find_so_prefers_in_package_wheel_location(tmp_path):
    """The wheel case: a libtab.so sitting inside the package dir (next to
    native.py) must be found FIRST, before the vendor/ fallback. Kills the
    first-candidate path-component mutants (pkg_dir/'libtab.so')."""
    pkg_dir = os.path.dirname(os.path.abspath(native.__file__))
    in_pkg = os.path.join(pkg_dir, "libtab.so")
    if os.path.exists(in_pkg):
        pytest.skip("a real in-package libtab.so is present; can't stage a fake")
    # copy the real vendor .so into the package dir to simulate a wheel
    import shutil

    shutil.copy2(native._find_so(), in_pkg)
    try:
        assert native._find_so() == in_pkg
    finally:
        os.remove(in_pkg)


def test_find_so_raises_when_missing(monkeypatch):
    """Kills the `os.path.exists(None)` mutant: with a path that does not
    exist, _find_so must raise NativeUnavailable — proving the existence
    check runs against the real candidate, not a constant."""
    monkeypatch.setattr(native.os.path, "exists", lambda p: False)
    with pytest.raises(native.NativeUnavailable):
        native._find_so()


def test_find_so_honors_libtab_so_override(tmp_path, monkeypatch):
    """The LIBTAB_SO env var must redirect _find_so to that path (used by
    the fuzz/sanitizer tooling to load libtab-asan.so). Kills the
    override-branch mutants: reading the wrong/absent env key, or
    inverting/nulling the existence check."""
    fake = tmp_path / "custom.so"
    fake.write_bytes(b"\x7fELF")  # any existing file
    monkeypatch.setenv("LIBTAB_SO", str(fake))
    assert native._find_so() == str(fake)


def test_find_so_override_must_exist(tmp_path, monkeypatch):
    """A LIBTAB_SO pointing at a nonexistent file must raise, not fall
    through to the default. Kills the `if os.path.exists(override)` and
    `os.path.exists(None)` mutants on the override branch."""
    monkeypatch.setenv("LIBTAB_SO", str(tmp_path / "nope.so"))
    with pytest.raises(native.NativeUnavailable, match="LIBTAB_SO"):
        native._find_so()


def test_find_so_ignores_unset_override(monkeypatch):
    """With LIBTAB_SO unset, _find_so returns the default vendor path —
    confirming the override reads the *right* env key (a mutant reading
    e.g. 'XXLIBTAB_SOXX' would always miss and this stays the default,
    but the positive override test above pins the exact key)."""
    monkeypatch.delenv("LIBTAB_SO", raising=False)
    path = native._find_so()
    assert path.endswith(os.path.join("vendor", "libtab.so"))
