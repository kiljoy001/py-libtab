"""Property-based tests (Hypothesis).

Unit tests pin specific cases; these assert *invariants* over many
machine-generated inputs — the round-trips and security properties that
must hold for every input, not just the examples a human thought to
write. Hypothesis shrinks any failure to a minimal reproducer.

The invariants here are the real contracts discussed throughout the
design: seal/unseal and b64 round-trip, sealing is non-deterministic and
tamper-evident, the writer/reader round-trip preserves any value the
writer accepts, and generated keypairs sign and verify.
"""
from __future__ import annotations

import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

native = pytest.importorskip("libtab.native")

if not os.path.exists(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")
):
    pytest.skip("vendor/libtab.so not built — run vendor/build.sh", allow_module_level=True)

Col = native.Column
Tab = native.Tabula
KEY = bytes(range(32))


# ── seal / unseal ─────────────────────────────────────────────────────

@given(pt=st.binary(max_size=4096))
@settings(max_examples=300)
def test_seal_unseal_roundtrip(pt):
    """unseal(k, seal(k, pt)) == pt for any plaintext, including empty."""
    assert native.unseal(KEY, native.seal(KEY, pt)) == pt


@given(pt=st.binary(min_size=1, max_size=256))
@settings(max_examples=200)
def test_seal_is_nondeterministic(pt):
    """A fresh random nonce per call means the same plaintext seals to a
    different blob every time — the security-critical property that makes
    key reuse safe. (Empty plaintext excluded: with no ciphertext bytes,
    only the 24-byte nonce varies, which is still enough, but a non-empty
    plaintext makes the intent unambiguous.)"""
    assert native.seal(KEY, pt) != native.seal(KEY, pt)


@given(pt=st.binary(min_size=1, max_size=256), i=st.integers(min_value=0))
@settings(max_examples=200)
def test_tampered_blob_fails_to_unseal(pt, i):
    """Flipping any single byte of a sealed blob makes unseal raise —
    AEAD (Poly1305) integrity. Covers the nonce, MAC, and ciphertext
    regions uniformly."""
    blob = bytearray(native.seal(KEY, pt))
    idx = i % len(blob)
    blob[idx] ^= 0x01
    with pytest.raises(native.TabulaError):
        native.unseal(KEY, bytes(blob))


@given(pt=st.binary(max_size=256), seed=st.binary(min_size=32, max_size=32))
@settings(max_examples=100)
def test_wrong_key_fails_to_unseal(pt, seed):
    """A key other than the sealing key never decrypts (indistinguishable
    from tampering, by design)."""
    other = seed if seed != KEY else bytes(32)
    blob = native.seal(KEY, pt)
    with pytest.raises(native.TabulaError):
        native.unseal(other, blob)


# ── base64 ────────────────────────────────────────────────────────────

@given(data=st.binary(max_size=4096))
@settings(max_examples=300)
def test_b64_roundtrip(data):
    """b64_decode(b64_encode(x)) == x for arbitrary bytes."""
    assert native.b64_decode(native.b64_encode(data)) == data


# ── writer / reader round-trip ────────────────────────────────────────

# .tab values follow the ndb grammar. A value that round-trips must avoid
# ndb's reserved characters: whitespace and quote (separate/quote tokens)
# and a LEADING '#' (ndb comment marker — a value starting with '#' is
# dropped as a comment on read; '#' mid-value is fine). This strategy
# generates values from the round-trippable domain; the invariant is that
# every such value survives write -> open -> get unchanged. (Same family
# as the unquoted-space footgun — see tests/test_native_errors.py.)
_ndb_char = st.characters(
    min_codepoint=0x21, max_codepoint=0x7E, blacklist_characters='"#'
)
_ndb_safe = st.builds(
    lambda first, rest: first + rest,
    _ndb_char,
    st.text(
        alphabet=st.characters(
            min_codepoint=0x21, max_codepoint=0x7E, blacklist_characters='"'
        ),
        max_size=63,
    ),
)


@given(key=_ndb_safe, val=_ndb_safe)
@settings(max_examples=200)
def test_write_open_get_roundtrip(tmp_path_factory, key, val):
    """Any ndb-safe value the writer accepts survives a full
    write -> commit -> open -> get cycle unchanged."""
    path = str(tmp_path_factory.mktemp("prop") / "t.tab")
    t = Tab.create(path, "t", [Col("id"), Col("v")])
    r = t.add_row("id", key)
    t.set(r, "v", val)
    t.commit()
    t.close()

    t2 = Tab.open(path)
    r2 = t2.search("id", key)[0]
    assert t2.get(r2, "v") == val
    t2.close()


# ── signing ───────────────────────────────────────────────────────────

@given(body=st.binary(min_size=1, max_size=512))
@settings(max_examples=100)
def test_keypair_sign_verify_roundtrip(tmp_path_factory, body):
    """A freshly generated keypair signs an arbitrary body, and
    verify_signed returns exactly that body."""
    sk, pk = native.keypair()
    path = str(tmp_path_factory.mktemp("prop") / "s.tab")
    t = Tab.create(path, "t", [Col("id"), Col("sig", type="SIGNED", signer="k")])
    r = t.add_row("id", "1")
    t.set_signed(r, "sig", body, sk)
    t.commit()
    t.close()

    t2 = Tab.open(path)
    r2 = t2.search("id", "1")[0]
    assert t2.verify_signed(r2, "sig", pk) == body
    t2.close()
