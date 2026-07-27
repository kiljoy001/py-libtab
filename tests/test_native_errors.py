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
import warnings

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
    with pytest.raises(native.TabulaUnavailable):
        native._find_so()


def test_open_missing_file_raises(tmp_path):
    with pytest.raises(native.TabulaError):
        native.Tabula.open(str(tmp_path / "does_not_exist.tab"))


def test_open_malformed_file_raises(tmp_path):
    path = tmp_path / "bad.tab"
    path.write_text("this is not ndb-shaped schema data\n")
    with pytest.raises(native.TabulaError):
        native.Tabula.open(str(path))


def test_open_hint_recognises_undeclared_column():
    # The raw C message for an unquoted-space value is baffling; _open_hint
    # turns it into an actionable explanation. Pure function — pin it directly.
    hint = native._open_hint("tab_open: row 0 has undeclared column %q%")
    assert "unquoted" in hint
    assert 'payee="Widget LLC"' in hint


def test_open_hint_silent_for_unrelated_errors():
    # A hint must not be appended to failures it can't explain.
    assert native._open_hint("tab_open: cannot open file: no such file") == ""


def test_open_unquoted_space_value_gives_hint(tmp_path):
    # A value with a space parses as two ndb tuples; the second word looks
    # like an undeclared column. open() should surface the space-quoting hint.
    path = tmp_path / "spacey.tab"
    t = native.Tabula.create(
        str(path), "payments",
        [native.Column("payee"), native.Column("amount")],
    )
    r = t.add_row("payee", "Widget")
    t.set(r, "amount", "1000")
    t.commit()
    t.close()
    # Inject the footgun: an unquoted space in the head value on disk.
    text = path.read_text().replace("payee=Widget", "payee=Widget LLC")
    path.write_text(text)
    with pytest.raises(native.TabulaError) as excinfo:
        native.Tabula.open(str(path))
    assert "unquoted" in str(excinfo.value)


def test_open_quoted_space_value_round_trips(tmp_path):
    # The correct form: a double-quoted value with a space opens cleanly and
    # the quotes are stripped on read.
    path = tmp_path / "quoted.tab"
    t = native.Tabula.create(
        str(path), "payments", [native.Column("payee")],
    )
    t.add_row("payee", '"Widget LLC"')
    t.commit()
    t.close()
    t2 = native.Tabula.open(str(path))
    assert t2.get(t2.iter_rows()[0], "payee") == "Widget LLC"
    t2.close()


def test_leading_hash_value_is_dropped_as_comment(tmp_path):
    # Known ndb-grammar constraint (documents the behavior, does not "fix"
    # it — the writer trusts the caller with representation). A value that
    # STARTS with '#' is parsed as an ndb comment on read, so it comes back
    # empty. Unlike the unquoted-space case (which fails to open), this
    # loses data silently — callers must avoid a leading '#' or quote it.
    path = tmp_path / "hash.tab"
    t = native.Tabula.create(str(path), "t", [native.Column("id"), native.Column("v")])
    r = t.add_row("id", "x")
    # set() warns about the silent-loss trap but still writes verbatim.
    with pytest.warns(UserWarning, match="ndb grammar treats as a comment"):
        t.set(r, "v", "#abc")
    t.commit()
    t.close()
    t2 = native.Tabula.open(str(path))
    r2 = t2.search("id", "x")[0]
    assert t2.get(r2, "v") == ""          # dropped as a comment
    t2.close()
    # '#' mid-value is fine — only a leading '#' is reserved.
    t3 = native.Tabula.create(str(tmp_path / "mid.tab"), "t", [native.Column("v")])
    t3.add_row("v", "a#b")
    t3.commit()
    t3.close()
    t4 = native.Tabula.open(str(tmp_path / "mid.tab"))
    assert t4.get(t4.iter_rows()[0], "v") == "a#b"
    t4.close()


def test_leading_hash_warns_on_set_and_add_row(tmp_path):
    # The sugar: because a leading '#' is lost silently, warn at WRITE time
    # (set and add_row's head value) so the caller finds out immediately.
    path = str(tmp_path / "w.tab")
    t = native.Tabula.create(path, "t", [native.Column("id"), native.Column("v")])
    with pytest.warns(UserWarning, match=r"starts with '#'"):
        r = t.add_row("id", "#head")
    with pytest.warns(UserWarning, match=r"Double-quote it"):
        t.set(r, "v", "#val")
    t.close()


def test_no_hash_warning_for_safe_values(tmp_path, recwarn):
    # Values that don't start with '#' (including '#' mid-value) must not warn.
    path = str(tmp_path / "s.tab")
    t = native.Tabula.create(path, "t", [native.Column("id"), native.Column("v")])
    r = t.add_row("id", "row")
    t.set(r, "v", "a#b")
    t.set(r, "v", "plain")
    t.close()
    assert not [w for w in recwarn.list if issubclass(w.category, UserWarning)]


def test_leading_hash_quoted_survives(tmp_path):
    # And the documented fix works: quoting a leading-'#' value keeps it
    # (no warning either, since the written value starts with a quote).
    path = str(tmp_path / "q.tab")
    t = native.Tabula.create(path, "t", [native.Column("id"), native.Column("v")])
    r = t.add_row("id", "x")
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any warning would fail here
        t.set(r, "v", '"#abc"')
    t.commit()
    t.close()
    t2 = native.Tabula.open(path)
    assert t2.get(t2.search("id", "x")[0], "v") == "#abc"
    t2.close()


def test_commit_to_missing_parent_dir_raises(tmp_path):
    # create() only builds the in-memory Tab; the filesystem write
    # happens at commit(). libtab.c's local-write path (tab_persist.c)
    # does NOT create missing parent directories — unlike a naive
    # implementation might assume, this must raise, not silently mkdir.
    t = native.Tabula.create(
        str(tmp_path / "sub" / "orders.tab"), "orders", [native.Column("id")]
    )
    t.add_row("id", "a")
    with pytest.raises(native.TabulaError):
        t.commit()
    t.close()


def test_set_unknown_column_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [native.Column("id")])
    r = t.add_row("id", "a")
    with pytest.raises(native.TabulaError):
        t.set(r, "nosuchcolumn", "x")
    t.close()


def test_clear_cell(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"), native.Column("k"),
    ])
    r = t.add_row("id", "a")
    t.set(r, "k", "x")
    assert t.get(r, "k") == "x"
    t.clear(r, "k")
    assert t.get(r, "k") is None
    t.close()


def test_clear_unknown_column_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [native.Column("id")])
    r = t.add_row("id", "a")
    with pytest.raises(native.TabulaError):
        t.clear(r, "nosuchcolumn")
    t.close()


def test_remove_row_twice_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [native.Column("id")])
    r = t.add_row("id", "a")
    t.remove_row(r)
    with pytest.raises(native.TabulaError):
        t.remove_row(r)
    t.close()


def test_remove_row_drops_from_iteration(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [native.Column("id")])
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
    with native.Tabula.create(path, "t", [native.Column("id")]) as t:
        t.add_row("id", "a")
        t.commit()
        assert t._closed is False
    assert t._closed is True


def test_close_is_idempotent(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [native.Column("id")])
    t.add_row("id", "a")
    t.commit()
    t.close()
    t.close()  # must not raise or double-free


def test_schema_introspection(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"),
        native.Column("pwhash", type="HASHED", algo="argon2id"),
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
    t = native.Tabula.create(path, "t", [
        native.Column("id"), native.Column("k"),
    ])
    r = t.add_row("id", "a")
    assert t.get(r, "k") is None
    t.close()


def test_search_no_matches_returns_empty(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"), native.Column("k"),
    ])
    t.add_row("id", "a")
    assert t.search("k", "nomatch") == []
    t.close()


def test_set_hashed_argon2id(tmp_path):
    pytest.importorskip("argon2")  # confirms C lib's argon2 support works too
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"),
        native.Column("pwhash", type="HASHED", algo="argon2id"),
    ])
    r = t.add_row("id", "a")
    t.set_hashed_argon2id(r, "pwhash", b"secret123")
    assert t.verify_hash(r, "pwhash", b"secret123") is True
    assert t.verify_hash(r, "pwhash", b"wrong") is False
    t.close()


def test_set_hashed_argon2id_wrong_column_type_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"), native.Column("plain"),
    ])
    r = t.add_row("id", "a")
    with pytest.raises(native.TabulaError):
        t.set_hashed_argon2id(r, "plain", b"secret123")
    t.close()


def test_verify_hash_on_empty_cell_returns_false(tmp_path):
    """tab_verify_hash returns 0 (not -1) for an empty cell — the C
    library treats "nothing to compare against" as a non-match, not an
    error, even though it also calls tab_seterror internally. The
    Tabula.verify_hash bool return only escalates rc < 0 to an
    exception, matching the C API's own success/failure boundary."""
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"),
        native.Column("pwhash", type="HASHED"),
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
    t = native.Tabula.open(str(path))
    r = t.iter_rows()[0]
    with pytest.raises(native.TabulaError):
        t.verify_hash(r, "pwhash", b"secret123")
    t.close()


def test_set_signed_wrong_column_type_raises(tmp_path):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"), native.Column("plain"),
    ])
    r = t.add_row("id", "a")
    sk, _pk = _monocypher_keypair(bytes(range(32)))
    with pytest.raises(native.TabulaError):
        t.set_signed(r, "plain", b"hello", sk)
    t.close()


def test_set_hashed_wrong_column_type_raises(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"), native.Column("plain"),
    ])
    r = t.add_row("id", "a")
    with pytest.raises(native.TabulaError):
        t.set_hashed(r, "plain", b"secret123")
    t.close()


def test_set_signed_rejects_short_key(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"), native.Column("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")
    with pytest.raises(native.TabulaError, match="64 bytes"):
        t.set_signed(r, "body", b"hello", b"short")
    t.close()


def test_verify_signed_rejects_short_key(tmp_path):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"), native.Column("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")
    sk, _pk = _monocypher_keypair(bytes(range(32)))
    t.set_signed(r, "body", b"hello", sk)
    with pytest.raises(native.TabulaError, match="32 bytes"):
        t.verify_signed(r, "body", b"short")
    t.close()


def test_verify_signed_wrong_key_raises(tmp_path):
    from tests.conftest import monocypher_keypair as _monocypher_keypair

    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [
        native.Column("id"), native.Column("body", type="SIGNED"),
    ])
    r = t.add_row("id", "a")
    sk, _pk = _monocypher_keypair(bytes(range(32)))
    _sk2, pk2 = _monocypher_keypair(bytes([9] * 32))
    t.set_signed(r, "body", b"hello", sk)
    with pytest.raises(native.TabulaError):
        t.verify_signed(r, "body", pk2)
    t.close()


def test_b64_decode_invalid_input_raises():
    with pytest.raises(native.TabulaError):
        native.b64_decode("not valid base64!!!")


def test_iter_rows_empty_table(tmp_path):
    path = str(tmp_path / "t.tab")
    t = native.Tabula.create(path, "t", [native.Column("id")])
    assert t.iter_rows() == []
    t.close()
