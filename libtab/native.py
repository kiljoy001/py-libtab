"""ctypes binding to the real objective-9c libtab C implementation.

Loads the actual libtab C source from objective-9c (unmodified),
compiled against a position-independent rebuild of the plan9port
libraries it depends on (lib9, libbio, libndb, libauth, libsec — see
vendor/build.sh). The 9P client mount path (tab_open_dial) is stubbed
out; it needs lib9pclient + libthread (Plan 9's own scheduler), a much
bigger dependency that a local-file Python library has no use for.

An earlier pure-Python reimplementation of the wire format was removed
(see libtab/__init__.py) after its SIGNED-column support turned out to
be silently incompatible with libtab.c's monocypher-based signatures.
This module is the only engine now; it is exactly as correct as the C
library it wraps, for every column type including SIGNED.

Requires vendor/libtab.so to exist. Run vendor/build.sh once first.
"""

from __future__ import annotations

import ctypes
import os
import secrets
from dataclasses import dataclass


class TabulaUnavailable(RuntimeError):
    pass


class TabulaError(RuntimeError):
    pass


class _NonNullHandle(ctypes.c_void_p):
    """A c_void_p argtype that rejects None at the ctypes dispatch step.

    ctypes calls from_param() on every argument whose declared argtype
    is set, before the actual C call executes — this runs regardless of
    what expression was used to construct the call, so it defends
    against a call site that was hand-edited (or corrupted) to pass a
    bare None instead of a real handle. A plain assertion on the
    Python-side variable can't catch this class of bug: it checks the
    variable, not the (possibly different) expression actually passed
    at the call site. Found via mutation testing — several mutants
    replaced `self._handle` with a literal `None` directly in a ctypes
    call, which no pre-call assertion on `self._handle` could detect,
    and which segfaults libtab.c (it does no null-checking of its own
    on Tab*/TabRow*/TabIter* arguments). Used for every Tab*/TabRow*/
    TabIter* argument; NOT used for optional c_char_p fields (e.g.
    TabColSpec's type/algo/signer), which legitimately accept None."""

    @classmethod
    def from_param(cls, value):
        if value is None:
            # message text is a pure diagnostic (not behavior); the
            # trailing pragma suppresses mutmut's XX-wrap/case-flip
            # string mutations, which are not worth killing.
            raise TabulaError("internal error: attempted to pass a null handle to a libtab C function that requires a live Tab/TabRow/TabIter — refusing rather than risking a segfault")  # pragma: no mutate
        # pragma: no mutate — this line is the dispatch point between
        # the validated value and ctypes' raw pointer marshaling; its only
        # observable failure mode is a process crash (a NULL reaches C),
        # which tests/test_aaa_subprocess_smoke.py verifies out-of-process.
        return super().from_param(value)  # pragma: no mutate


class _NonNullCharP(ctypes.c_char_p):
    """c_char_p argtype that rejects None. Same rationale as
    _NonNullHandle: libtab.c runs strlen/memcpy on string arguments
    without null-checking, so a call site corrupted to pass None
    segfaults instead of raising. Used for string arguments the C API
    requires (paths, column names, cell values, b64 input buffers);
    NOT used for the genuinely optional strings in _TabColSpec, which
    are struct fields rather than call arguments anyway."""

    @classmethod
    def from_param(cls, value):
        if value is None:
            raise TabulaError("internal error: attempted to pass a null string to a libtab C function that requires one — refusing rather than risking a segfault")  # pragma: no mutate
        # pragma: no mutate — dispatch point; see _NonNullHandle.from_param.
        return super().from_param(value)  # pragma: no mutate


class _NonNullIntP:
    """POINTER(c_int)-shaped argtype that rejects None. libtab's
    out-parameters (e.g. tab_b64_decode's *outlen) are written
    unconditionally by the C code; passing NULL is an instant
    null-pointer write. ctypes' own POINTER(c_int) accepts None as a
    NULL synonym by design, so this wrapper closes that hole."""

    _base = ctypes.POINTER(ctypes.c_int)

    @classmethod
    def from_param(cls, value):
        if value is None:
            raise TabulaError("internal error: attempted to pass a null out-parameter pointer to a libtab C function that writes through it — refusing rather than risking a segfault")  # pragma: no mutate
        # pragma: no mutate — dispatch point; see _NonNullHandle.from_param.
        return cls._base.from_param(value)  # pragma: no mutate


# The lowest address any real allocation can live at. Page zero (and on
# every mainstream OS, the first 4 KiB at minimum) is never mapped, so a
# "pointer" below this is either NULL or a small integer that leaked
# into an address position (e.g. a length passed where a pointer
# belongs — an exact bug class mutation testing produced here, via
# ctypes.string_at(outlen.value) instead of string_at(ptr, outlen.value),
# which reads from address==length and segfaults).
_MIN_PLAUSIBLE_ADDR = 4096


def _address_is_plausible(ptr) -> bool:
    """Pure predicate: is `ptr` a value it's safe to hand to a raw
    memory read? Kept separate from _string_at deliberately so its
    logic can be unit-tested directly with lethal inputs (0, small
    ints, None) without any memory access on the line of fire — a
    mutant of this predicate then dies as a clean assertion failure
    instead of a segfault."""
    return isinstance(ptr, int) and ptr >= _MIN_PLAUSIBLE_ADDR


def _string_at(ptr, size: int = -1) -> bytes:
    """ctypes.string_at with the address validated first. Raises
    TabulaError instead of letting an implausible address reach
    the raw memory read (which would segfault, not raise)."""
    if not _address_is_plausible(ptr):
        raise TabulaError(f"internal error: implausible memory address {ptr!r} passed where a C-heap pointer was expected — refusing rather than risking a segfault")  # pragma: no mutate
    if size >= 0:
        # pragma: no mutate on the raw reads below — these ARE the guarded
        # memory access; a mutant here (e.g. string_at(size), string_at(None))
        # can only manifest as a segfault, which the aaa subprocess smoke
        # tests detect by child exit code. All decision logic above them is
        # separately mutation-tested via _address_is_plausible.
        return ctypes.string_at(ptr, size)  # pragma: no mutate
    return ctypes.string_at(ptr)  # pragma: no mutate


def _find_so() -> str:
    # LIBTAB_SO overrides everything — used by the fuzz/sanitizer tooling
    # to load vendor/libtab-asan.so (the ASan+UBSan build) in place of the
    # normal -O2 build. Unset in normal use.
    override = os.environ.get("LIBTAB_SO")
    if override:
        if not os.path.exists(override):
            raise TabulaUnavailable(f"LIBTAB_SO={override} does not exist")  # pragma: no mutate
        return override

    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(pkg_dir)
    # Two locations, checked in order:
    #   1. inside the installed package (libtab/libtab.so) — where a
    #      built wheel ships the compiled library;
    #   2. vendor/libtab.so at the repo root — a source checkout that ran
    #      vendor/build.sh (dev workflow).
    for candidate in (
        os.path.join(pkg_dir, "libtab.so"),
        os.path.join(repo_root, "vendor", "libtab.so"),
    ):
        if os.path.exists(candidate):
            return candidate
    raise TabulaUnavailable(f"libtab.so not found (looked in {pkg_dir} and {repo_root}/vendor) — install a wheel, or run vendor/build.sh in a source checkout (needs a C toolchain)")  # pragma: no mutate


class _TabColSpec(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("type", ctypes.c_char_p),
        ("algo", ctypes.c_char_p),
        ("signer", ctypes.c_char_p),
    ]


def _load() -> ctypes.CDLL:
    lib = ctypes.CDLL(_find_so())

    lib.tab_create.restype = ctypes.c_void_p
    lib.tab_create.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.POINTER(_TabColSpec), ctypes.c_int,
    ]
    lib.tab_add_row.restype = ctypes.c_void_p
    lib.tab_add_row.argtypes = [_NonNullHandle, ctypes.c_char_p, ctypes.c_char_p]
    lib.tab_set.restype = ctypes.c_int
    lib.tab_set.argtypes = [_NonNullHandle, _NonNullHandle, ctypes.c_char_p, ctypes.c_char_p]
    lib.tab_clear.restype = ctypes.c_int
    lib.tab_clear.argtypes = [_NonNullHandle, _NonNullHandle, ctypes.c_char_p]
    lib.tab_remove_row.restype = ctypes.c_int
    lib.tab_remove_row.argtypes = [_NonNullHandle, _NonNullHandle]

    lib.tab_open.restype = ctypes.c_void_p
    lib.tab_open.argtypes = [ctypes.c_char_p]
    lib.tab_close.restype = None
    lib.tab_close.argtypes = [_NonNullHandle]
    lib.tab_commit.restype = ctypes.c_int
    lib.tab_commit.argtypes = [_NonNullHandle]

    lib.tab_lasterror.restype = ctypes.c_char_p
    lib.tab_lasterror.argtypes = []

    lib.tab_schema_name.restype = ctypes.c_char_p
    lib.tab_schema_name.argtypes = [_NonNullHandle]
    lib.tab_ncolumns.restype = ctypes.c_int
    lib.tab_ncolumns.argtypes = [_NonNullHandle]
    lib.tab_colname.restype = ctypes.c_char_p
    lib.tab_colname.argtypes = [_NonNullHandle, ctypes.c_int]
    lib.tab_coltype.restype = ctypes.c_char_p
    lib.tab_coltype.argtypes = [_NonNullHandle, ctypes.c_int]
    lib.tab_col_attr.restype = ctypes.c_char_p
    lib.tab_col_attr.argtypes = [_NonNullHandle, ctypes.c_char_p, ctypes.c_char_p]

    lib.tab_iter.restype = ctypes.c_void_p
    lib.tab_iter.argtypes = [_NonNullHandle]
    lib.tab_search.restype = ctypes.c_void_p
    lib.tab_search.argtypes = [_NonNullHandle, ctypes.c_char_p, ctypes.c_char_p]
    lib.tab_iter_next.restype = ctypes.c_void_p
    lib.tab_iter_next.argtypes = [_NonNullHandle]
    lib.tab_iter_close.restype = None
    lib.tab_iter_close.argtypes = [_NonNullHandle]

    lib.tab_get.restype = ctypes.c_char_p
    lib.tab_get.argtypes = [_NonNullHandle, ctypes.c_char_p]

    lib.tab_b64_encode.restype = ctypes.c_void_p
    lib.tab_b64_encode.argtypes = [_NonNullCharP, ctypes.c_int]
    lib.tab_b64_decode.restype = ctypes.c_void_p
    lib.tab_b64_decode.argtypes = [_NonNullCharP, _NonNullIntP]

    lib.tab_set_hashed.restype = ctypes.c_int
    lib.tab_set_hashed.argtypes = [
        _NonNullHandle, _NonNullHandle, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
    ]
    lib.tab_set_hashed_argon2id.restype = ctypes.c_int
    lib.tab_set_hashed_argon2id.argtypes = [
        _NonNullHandle, _NonNullHandle, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
    ]
    lib.tab_verify_hash.restype = ctypes.c_int
    lib.tab_verify_hash.argtypes = [
        _NonNullHandle, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
    ]

    lib.tab_set_signed.restype = ctypes.c_int
    lib.tab_set_signed.argtypes = [
        _NonNullHandle, _NonNullHandle, ctypes.c_char_p,
        ctypes.c_char_p, ctypes.c_int, ctypes.c_char * 64,
    ]
    lib.tab_verify_signed.restype = ctypes.c_void_p
    lib.tab_verify_signed.argtypes = [
        _NonNullHandle, ctypes.c_char_p, ctypes.c_char * 32, _NonNullIntP,
    ]

    # monocypher XChaCha20-Poly1305 AEAD, used by seal()/unseal(). These
    # are the raw crypto primitives (not tab_* wrappers); libtab links
    # monocypher so they are exported from the same .so.
    #   void crypto_aead_lock(ct, mac[16], key[32], nonce[24], ad, ad_size,
    #                         plaintext, text_size)
    #   int  crypto_aead_unlock(pt, mac[16], key[32], nonce[24], ad, ad_size,
    #                           ciphertext, text_size)  -> 0 ok, -1 forged
    # The output buffer (arg 0) and the plaintext/ciphertext input (arg 6)
    # are _NonNullCharP: passing None there would segfault the AEAD, which
    # does no null-checking. `ad` (arg 4) stays plain c_char_p — we call
    # with ad=None, ad_size=0 (no additional data), which is legitimate.
    lib.crypto_aead_lock.restype = None
    lib.crypto_aead_lock.argtypes = [
        _NonNullCharP, ctypes.c_char * 16, ctypes.c_char * 32, ctypes.c_char * 24,
        ctypes.c_char_p, ctypes.c_size_t, _NonNullCharP, ctypes.c_size_t,
    ]
    lib.crypto_aead_unlock.restype = ctypes.c_int
    lib.crypto_aead_unlock.argtypes = [
        _NonNullCharP, ctypes.c_char * 16, ctypes.c_char * 32, ctypes.c_char * 24,
        ctypes.c_char_p, ctypes.c_size_t, _NonNullCharP, ctypes.c_size_t,
    ]

    # crypto_eddsa_key_pair(secret_key[64], public_key[32], seed[32]) — the
    # monocypher key generator. It overwrites `seed` with the secret key, so
    # keypair() copies the secret out and discards the seed buffer.
    lib.crypto_eddsa_key_pair.restype = None
    lib.crypto_eddsa_key_pair.argtypes = [
        ctypes.c_char * 64, ctypes.c_char * 32, ctypes.c_char * 32,
    ]

    return lib


_lib: ctypes.CDLL | None = None


def _get_lib() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        _lib = _load()
    return _lib


# Diagnostic fallback text; not behavior — its exact wording is not
# asserted, so its string mutants are pragma-suppressed at use below.
_UNKNOWN_ERROR = "unknown error"  # pragma: no mutate


def _check_error(lib: ctypes.CDLL, context: str) -> None:
    err = lib.tab_lasterror()
    msg = err.decode() if err else _UNKNOWN_ERROR
    if msg != "no error":
        raise TabulaError(f"{context}: {msg}")


def _open_hint(msg: str) -> str:
    """Return a friendlier explanation to append to a tab_open failure, or
    an empty string if the failure is not a recognised pattern.

    libtab values follow the ndb grammar: whitespace separates
    attribute/value pairs, so a value containing an unquoted space (e.g.
    ``payee=Widget LLC``) is parsed as *two* tuples, and the second word
    surfaces as an "undeclared column". That raw message is baffling to
    someone who never wrote a column by that name, so we recognise the
    pattern and point at the real cause. It is a *hint*, not a certain
    diagnosis (a genuinely malformed file can also trip this), so the
    wording hedges accordingly.
    """
    if "undeclared column" in msg:  # pragma: no mutate
        return (  # pragma: no mutate
            " — this usually means a value in the file contains an unquoted "
            "space. libtab values follow the ndb grammar, so a value with a "
            'space must be double-quoted, e.g. payee="Widget LLC".'
        )
    return ""  # pragma: no mutate


def _require_bytes(value: object, name: str) -> bytes:
    """Validate a buffer before it crosses into a (pointer, length) C
    call. libtab.c trusts its caller completely — it does no bounds or
    null-pointer checking of its own — so a caller (or an internal bug)
    that hands a mismatched pointer/length pair here doesn't raise a
    Python exception, it segfaults the whole interpreter. Confirmed via
    mutation testing: a mutant that passed None in place of a real
    bytes buffer while leaving len(original_buffer) as the length
    argument crashed the process outright. Every value that reaches a
    ctypes.c_char_p buffer argument must be validated as real bytes
    first, not just assumed correct by type annotation."""
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    return value


@dataclass
class Column:
    name: str
    type: str | None = None
    algo: str | None = None
    signer: str | None = None


class Row:
    """Opaque row handle. Read cells via Tabula.get(row, col).

    tab_remove_row() frees the underlying C TabRow struct on success
    (see tab_rowmap_delete in tab_rowmap.c) — the pointer becomes
    dangling. libtab.c's own guard only catches nil/t->nilrow, not an
    already-freed-and-reused row, so passing a stale Row back
    into any tab_* call after removal is a use-after-free at the C
    level (confirmed: it segfaults, not raises). _freed tracks this on
    the Python side so every wrapper method can raise a clean
    TabulaError instead of ever handing a stale pointer to C.
    """

    def __init__(self, ptr: int):
        self._ptr = ptr
        self._freed = False

    def _check_live(self) -> None:
        """Checks `is not False`, not truthiness, deliberately: _freed
        starts as the literal False and is only ever set to the literal
        True by remove_row(). Any other value (a corrupted sentinel, a
        stray None) must fail CLOSED — i.e. still raise — rather than
        silently being treated as "not freed" just because it happens to
        be falsy. A truthiness check here would let a corrupted _freed
        silently permit a use-after-free dereference instead of raising."""
        if self._freed is not False:
            raise TabulaError("this row was already removed (tab_remove_row frees the underlying C struct) — the handle is no longer valid")  # pragma: no mutate


class Tabula:
    """ctypes-backed Table, wrapping the real libtab.c Tab handle."""

    def __init__(self, handle: int):
        self._lib = _get_lib()
        self._handle = handle
        self._closed = False

    def _check_open(self) -> None:
        """tab_close() frees the underlying C Tab struct. Confirmed via
        mutation testing + manual reproduction: calling a method on a
        closed Tabula does not reliably raise or crash — it can
        silently return garbage data read from freed/reused memory
        (observed: colname(0) returning an unrelated character after
        close()). Every method touching self._handle must check this
        first.

        Checks `is not False`, not truthiness, deliberately: _closed
        starts as the literal False and is only ever set to the literal
        True by close(). Any other value must fail CLOSED (still raise)
        rather than being silently treated as "still open" just because
        it happens to be falsy — this is what makes a corrupted _closed
        value (e.g. from an internal bug) segfault-proof instead of a
        silent use-after-free."""
        if self._closed is not False:
            raise TabulaError("this table is closed (tab_close frees the underlying C struct) — the handle is no longer valid")  # pragma: no mutate

    @classmethod
    def create(cls, path: str, schema_name: str, columns: list[Column]) -> Tabula:
        lib = _get_lib()
        specs = (_TabColSpec * len(columns))(*[
            _TabColSpec(
                c.name.encode(),
                c.type.encode() if c.type else None,
                c.algo.encode() if c.algo else None,
                c.signer.encode() if c.signer else None,
            )
            for c in columns
        ])
        handle = lib.tab_create(path.encode(), schema_name.encode(), specs, len(columns))
        if not handle:
            _check_error(lib, "tab_create")
            raise TabulaError("tab_create failed with no error message")  # pragma: no mutate
        return cls(handle)

    @classmethod
    def open(cls, path: str) -> Tabula:
        lib = _get_lib()
        handle = lib.tab_open(path.encode())
        if not handle:
            try:
                _check_error(lib, "tab_open")
            except TabulaError as e:
                hint = _open_hint(str(e))
                if hint:
                    raise TabulaError(f"{e}{hint}") from e
                raise
            raise TabulaError("tab_open failed with no error message")  # pragma: no mutate
        return cls(handle)

    def add_row(self, head_attr: str, head_val: str) -> Row:
        self._check_open()
        r = self._lib.tab_add_row(self._handle, head_attr.encode(), head_val.encode())
        if not r:
            _check_error(self._lib, "tab_add_row")
            raise TabulaError("tab_add_row failed with no error message")  # pragma: no mutate
        return Row(r)

    def set(self, row: Row, col: str, value: str) -> None:
        self._check_open()
        row._check_live()
        rc = self._lib.tab_set(self._handle, row._ptr, col.encode(), value.encode())
        if rc:  # 0 = success, -1 = error (libtab.h contract)
            _check_error(self._lib, "tab_set")

    def get(self, row: Row, col: str) -> str | None:
        self._check_open()
        row._check_live()
        v = self._lib.tab_get(row._ptr, col.encode())
        return v.decode() if v is not None else None

    def clear(self, row: Row, col: str) -> None:
        self._check_open()
        row._check_live()
        rc = self._lib.tab_clear(self._handle, row._ptr, col.encode())
        if rc:  # 0 = success, -1 = error
            _check_error(self._lib, "tab_clear")

    def remove_row(self, row: Row) -> None:
        self._check_open()
        row._check_live()
        rc = self._lib.tab_remove_row(self._handle, row._ptr)
        if rc:  # 0 = success, -1 = error
            _check_error(self._lib, "tab_remove_row")
        row._freed = True
        # Verify the postcondition with a real runtime check (not an
        # assert, which `python -O` strips): if the assignment above were
        # ever corrupted to `row._freed = False`, the freed-row guard
        # can't tell it from "never removed" (both are literally False)
        # and a later call on this row would use-after-free. This must
        # hold in every build, optimized or not.
        if row._freed is not True:  # pragma: no cover - defensive invariant
            raise TabulaError("internal invariant violated: row not marked freed after remove")  # pragma: no mutate

    def commit(self) -> None:
        """Persist the in-memory table to its path.

        Does NOT create missing parent directories — the path's
        directory must already exist, or this raises TabulaError.
        """
        self._check_open()
        rc = self._lib.tab_commit(self._handle)
        if rc:  # 0 = success, -1 = error
            _check_error(self._lib, "tab_commit")

    def close(self) -> None:
        # is False, not "not truthy": a corrupted _closed must not
        # silently permit a second tab_close() (double free) or
        # silently skip the first one — see _check_open's docstring.
        if self._closed is False:
            self._lib.tab_close(self._handle)
            self._closed = True
            # Real runtime check (not an assert, which `python -O`
            # strips): same invariant as remove_row's. If corrupted to
            # `self._closed = False`, _check_open can't distinguish it
            # from "never closed" and the next call use-after-frees.
            if self._closed is not True:  # pragma: no cover - defensive invariant
                raise TabulaError("internal invariant violated: table not marked closed")  # pragma: no mutate

    def __enter__(self) -> Tabula:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def schema_name(self) -> str:
        self._check_open()
        v = self._lib.tab_schema_name(self._handle)
        return v.decode() if v else ""

    @property
    def ncolumns(self) -> int:
        self._check_open()
        return self._lib.tab_ncolumns(self._handle)

    def colname(self, idx: int) -> str | None:
        self._check_open()
        v = self._lib.tab_colname(self._handle, idx)
        return v.decode() if v else None

    def coltype(self, idx: int) -> str | None:
        self._check_open()
        v = self._lib.tab_coltype(self._handle, idx)
        return v.decode() if v else None

    def col_attr(self, col: str, key: str) -> str | None:
        self._check_open()
        v = self._lib.tab_col_attr(self._handle, col.encode(), key.encode())
        return v.decode() if v else None

    def _drain_iter(self, it: int, context: str) -> list[Row]:
        """Walk a TabIter to exhaustion into a list, always closing it.
        Shared by iter_rows() and search(), which differ only in how the
        iterator is opened."""
        if not it:
            _check_error(self._lib, context)
            raise TabulaError(f"{context} failed with no error message")  # pragma: no mutate
        rows = []
        try:
            while True:
                r = self._lib.tab_iter_next(it)
                if not r:
                    break
                rows.append(Row(r))
        finally:
            self._lib.tab_iter_close(it)
        return rows

    def iter_rows(self) -> list[Row]:
        self._check_open()
        return self._drain_iter(self._lib.tab_iter(self._handle), "tab_iter")

    def search(self, col: str, value: str) -> list[Row]:
        self._check_open()
        it = self._lib.tab_search(self._handle, col.encode(), value.encode())
        return self._drain_iter(it, "tab_search")

    def set_hashed(self, row: Row, col: str, preimage: bytes) -> None:
        self._check_open()
        row._check_live()
        preimage = _require_bytes(preimage, "preimage")
        rc = self._lib.tab_set_hashed(self._handle, row._ptr, col.encode(), preimage, len(preimage))
        if rc:  # 0 = success, -1 = error
            _check_error(self._lib, "tab_set_hashed")

    def set_hashed_argon2id(self, row: Row, col: str, preimage: bytes) -> None:
        self._check_open()
        row._check_live()
        preimage = _require_bytes(preimage, "preimage")
        rc = self._lib.tab_set_hashed_argon2id(
            self._handle, row._ptr, col.encode(), preimage, len(preimage)
        )
        if rc:  # 0 = success, -1 = error
            _check_error(self._lib, "tab_set_hashed_argon2id")

    def verify_hash(self, row: Row, col: str, preimage: bytes) -> bool:
        row._check_live()
        preimage = _require_bytes(preimage, "preimage")
        rc = self._lib.tab_verify_hash(row._ptr, col.encode(), preimage, len(preimage))
        if rc < 0:
            _check_error(self._lib, "tab_verify_hash")
        return rc == 1

    def set_signed(self, row: Row, col: str, body: bytes, signer_sk: bytes) -> None:
        self._check_open()
        row._check_live()
        body = _require_bytes(body, "body")
        signer_sk = _require_bytes(signer_sk, "signer_sk")
        if len(signer_sk) != 64:
            raise TabulaError("signer_sk must be 64 bytes (monocypher seed+pubkey form)")  # pragma: no mutate
        sk_buf = ctypes.c_char.__mul__(64)(*[bytes([b]) for b in signer_sk])
        rc = self._lib.tab_set_signed(self._handle, row._ptr, col.encode(), body, len(body), sk_buf)
        if rc:  # 0 = success, -1 = error
            _check_error(self._lib, "tab_set_signed")

    def verify_signed(self, row: Row, col: str, signer_pk: bytes) -> bytes:
        row._check_live()
        signer_pk = _require_bytes(signer_pk, "signer_pk")
        if len(signer_pk) != 32:
            raise TabulaError("signer_pk must be 32 bytes")  # pragma: no mutate
        pk_buf = ctypes.c_char.__mul__(32)(*[bytes([b]) for b in signer_pk])
        outlen = ctypes.c_int(0)  # pragma: no mutate — C overwrites outlen; initial value is dead
        ptr = self._lib.tab_verify_signed(row._ptr, col.encode(), pk_buf, ctypes.byref(outlen))
        if not ptr:
            _check_error(self._lib, "tab_verify_signed")
            raise TabulaError("tab_verify_signed failed with no error message")  # pragma: no mutate
        return _string_at(ptr, outlen.value)

    def set_sealed(self, row: Row, col: str, plaintext: bytes, key: bytes) -> None:
        """Encrypt `plaintext` under `key` and store it as a self-
        describing `sealed:<base64url>` cell in an ORDINARY (untyped)
        column. Unlike HASHED/SIGNED, sealing is a py-libtab convention
        at the application layer — libtab's C only recognizes HASHED and
        SIGNED column types, so a `type=SEALED` column would make the
        file unreadable by stock libtab. Storing the sealed blob in a
        plain column keeps the file fully compatible; the cell is inert
        text that only the key holder can decrypt via get_sealed()."""
        self._check_open()
        blob = seal(key, plaintext)  # validates key/plaintext are bytes
        self.set(row, col, "sealed:" + b64_encode(blob))

    def get_sealed(self, row: Row, col: str, key: bytes) -> bytes:
        """Read a cell written by set_sealed() and decrypt it under
        `key`. Raises TabulaError if the cell isn't a sealed blob,
        or if the key is wrong / the blob was tampered with."""
        self._check_open()
        cell = self.get(row, col)
        if cell is None or not cell.startswith("sealed:"):
            raise TabulaError(f"cell {col!r} is not a sealed value")  # pragma: no mutate
        blob = b64_decode(cell[len("sealed:"):])
        return unseal(key, blob)  # validates key, raises on wrong key/tamper


def b64_encode(data: bytes) -> str:
    data = _require_bytes(data, "data")
    lib = _get_lib()
    ptr = lib.tab_b64_encode(data, len(data))
    if not ptr:
        _check_error(lib, "tab_b64_encode")
        raise TabulaError("tab_b64_encode failed with no error message")  # pragma: no mutate
    return _string_at(ptr).decode()


def b64_decode(s: str) -> bytes:
    lib = _get_lib()
    outlen = ctypes.c_int(0)  # pragma: no mutate — C overwrites outlen; initial value is dead
    ptr = lib.tab_b64_decode(s.encode(), ctypes.byref(outlen))
    if not ptr:
        _check_error(lib, "tab_b64_decode")
        raise TabulaError("tab_b64_decode failed with no error message")  # pragma: no mutate
    return _string_at(ptr, outlen.value)


# ---- authenticated encryption (sealing) ----------------------------------
#
# seal()/unseal() provide confidentiality: unlike SIGNED (which stores the
# body in the clear and only proves authenticity) and HASHED (an
# irreversible digest), a sealed blob's plaintext cannot be recovered
# without the key. XChaCha20-Poly1305 via monocypher's crypto_aead_lock,
# with a fresh random nonce per call.
#
# Envelope is byte-for-byte the same as objective-9c's o9_encrypt:
#     nonce[24] || mac[16] || ciphertext
# so a value sealed here is interoperable with an o9 `secret` field under
# the same 32-byte key (o9 hex-encodes this envelope at the field layer;
# the SEALED *cell* format below base64url-tags the identical bytes).

SEAL_KEY_LEN = 32
SEAL_NONCE_LEN = 24
SEAL_MAC_LEN = 16
_SEAL_HEADER_LEN = SEAL_NONCE_LEN + SEAL_MAC_LEN  # 40

# Ed25519 (monocypher variant) key sizes. These are fixed by the algorithm,
# not tunable strength knobs: a public key is a 32-byte curve point, the seed
# is 32 bytes = 256 bits of entropy (~128-bit security), and the secret key is
# 64 bytes because monocypher stores the 32-byte seed concatenated with the
# 32-byte public key (a caching convention, not 64 bytes of secret entropy).
SIGN_SEED_LEN = 32
SIGN_PUBLIC_KEY_LEN = 32
SIGN_SECRET_KEY_LEN = 64


def _keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Derive an Ed25519 keypair from an exact 32-byte `seed`.

    Returns ``(secret_key[64], public_key[32])`` — the tuple that
    ``Tabula.set_signed`` (secret key) and ``verify_signed`` (public
    key) consume directly.

    SECURITY: the seed *is* the private key material. Its secrecy and
    randomness are the entire security of every signature made with the
    result. Prefer ``keypair()``, which draws a fresh CSPRNG seed for you.
    Only pass a seed here if you are deliberately reproducing a key from
    material you already generated securely — never from a password, a
    counter, or any low-entropy value.
    """
    seed = _require_bytes(seed, "seed")
    if len(seed) != SIGN_SEED_LEN:
        raise TabulaError("seed must be 32 bytes")  # pragma: no mutate
    lib = _get_lib()

    sk_buf = (ctypes.c_char * SIGN_SECRET_KEY_LEN)()
    pk_buf = (ctypes.c_char * SIGN_PUBLIC_KEY_LEN)()
    seed_buf = (ctypes.c_char * SIGN_SEED_LEN)(*[bytes([b]) for b in seed])
    lib.crypto_eddsa_key_pair(sk_buf, pk_buf, seed_buf)
    return bytes(sk_buf), bytes(pk_buf)


def keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 signing keypair.

    Returns ``(secret_key, public_key)``:

    - ``secret_key`` (64 bytes) — keep it secret; pass it to
      ``Tabula.set_signed`` to sign a cell.
    - ``public_key`` (32 bytes) — share it freely; pass it to
      ``Tabula.verify_signed`` to check a signature.

    The seed is drawn from ``secrets.token_bytes`` (the OS CSPRNG), so
    each call yields an independent, unpredictable key — you never handle
    raw entropy or ctypes buffers yourself.
    """
    return _keypair_from_seed(secrets.token_bytes(SIGN_SEED_LEN))


def seal(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt `plaintext` under a 32-byte `key`, returning a
    self-contained blob (nonce || mac || ciphertext). A fresh random
    nonce is drawn per call, so reusing the same key is safe and there
    is no nonce argument to get wrong."""
    key = _require_bytes(key, "key")
    plaintext = _require_bytes(plaintext, "plaintext")
    if len(key) != SEAL_KEY_LEN:
        raise TabulaError("key must be 32 bytes")  # pragma: no mutate
    lib = _get_lib()

    nonce = os.urandom(SEAL_NONCE_LEN)
    key_buf = (ctypes.c_char * SEAL_KEY_LEN)(*[bytes([b]) for b in key])
    nonce_buf = (ctypes.c_char * SEAL_NONCE_LEN)(*[bytes([b]) for b in nonce])
    mac_buf = (ctypes.c_char * SEAL_MAC_LEN)()
    ct_buf = (ctypes.c_char * len(plaintext))()   # zero-length is valid

    # ad=None, ad_size=0: no additional data. The buffer args are guarded
    # by _NonNullCharP; a mutation of the ad_size constant here can only
    # crash (reads from a NULL ad), so pragma it — the seal round-trip and
    # the subprocess null-arg probes cover the real behavior.
    lib.crypto_aead_lock(ct_buf, mac_buf, key_buf, nonce_buf, None, 0, plaintext, len(plaintext))  # pragma: no mutate
    return nonce + bytes(mac_buf) + bytes(ct_buf)[: len(plaintext)]


def unseal(key: bytes, blob: bytes) -> bytes:
    """Decrypt a blob produced by seal() under the same 32-byte `key`.
    Returns the plaintext, or raises TabulaError if the key is
    wrong or the blob was tampered with (Poly1305 authentication fails)
    — the two are indistinguishable, by design."""
    key = _require_bytes(key, "key")
    blob = _require_bytes(blob, "blob")
    if len(key) != SEAL_KEY_LEN:
        raise TabulaError("key must be 32 bytes")  # pragma: no mutate
    if len(blob) < _SEAL_HEADER_LEN:
        raise TabulaError("sealed blob too short")  # pragma: no mutate
    lib = _get_lib()

    nonce = blob[:SEAL_NONCE_LEN]
    mac = blob[SEAL_NONCE_LEN:_SEAL_HEADER_LEN]
    ciphertext = blob[_SEAL_HEADER_LEN:]

    key_buf = (ctypes.c_char * SEAL_KEY_LEN)(*[bytes([b]) for b in key])
    nonce_buf = (ctypes.c_char * SEAL_NONCE_LEN)(*[bytes([b]) for b in nonce])
    mac_buf = (ctypes.c_char * SEAL_MAC_LEN)(*[bytes([b]) for b in mac])
    pt_buf = (ctypes.c_char * len(ciphertext))()   # zero-length is valid

    # ad=None, ad_size=0; see seal() — same pragma rationale.
    rc = lib.crypto_aead_unlock(pt_buf, mac_buf, key_buf, nonce_buf, None, 0, ciphertext, len(ciphertext))  # pragma: no mutate
    if rc != 0:
        raise TabulaError("unseal failed: wrong key or tampered blob")  # pragma: no mutate
    return bytes(pt_buf)[: len(ciphertext)]
