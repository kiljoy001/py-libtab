"""Coverage for the keypair() / _keypair_from_seed() signing-key helpers.

These wrap monocypher's crypto_eddsa_key_pair so callers never touch
ctypes. The security-critical properties: correct key sizes, fresh
randomness per call, seed-length validation, and that the generated keys
actually sign and verify through Tabula.
"""
from __future__ import annotations

import os

import pytest

native = pytest.importorskip("libtab.native")

if not os.path.exists(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "libtab.so")
):
    pytest.skip("vendor/libtab.so not built — run vendor/build.sh", allow_module_level=True)


def test_keypair_sizes():
    sk, pk = native.keypair()
    assert len(sk) == native.SIGN_SECRET_KEY_LEN == 64
    assert len(pk) == native.SIGN_PUBLIC_KEY_LEN == 32


def test_keypair_is_fresh_each_call():
    sk1, pk1 = native.keypair()
    sk2, pk2 = native.keypair()
    assert sk1 != sk2
    assert pk1 != pk2


def test_keypair_from_seed_is_deterministic():
    seed = bytes(range(32))
    a = native._keypair_from_seed(seed)
    b = native._keypair_from_seed(seed)
    assert a == b


def test_keypair_from_seed_different_seeds_differ():
    a = native._keypair_from_seed(bytes(range(32)))
    b = native._keypair_from_seed(bytes(range(1, 33)))
    assert a != b


def test_keypair_from_seed_accepts_exactly_32_bytes():
    # The boundary must be exactly SIGN_SEED_LEN: 32 works...
    sk, pk = native._keypair_from_seed(b"\x00" * 32)
    assert len(sk) == 64 and len(pk) == 32


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_keypair_from_seed_rejects_off_by_one_lengths(length):
    # ...and anything else — including 31 and 33 — is rejected. This pins
    # the guard to the exact constant (a mutant that widens it to some
    # unrelated value would let 31/33 through and fail here).
    with pytest.raises(native.TabulaError, match="32 bytes"):
        native._keypair_from_seed(b"\x00" * length)


def test_keypair_from_seed_rejects_non_bytes():
    with pytest.raises(TypeError):
        native._keypair_from_seed("not bytes")  # type: ignore[arg-type]


def test_keypair_secret_key_embeds_public_key():
    # monocypher's 64-byte secret key is seed(32) || public_key(32); the
    # trailing 32 bytes must equal the returned public key.
    sk, pk = native.keypair()
    assert sk[32:] == pk


def test_keypair_signs_and_verifies(tmp_path):
    sk, pk = native.keypair()
    path = str(tmp_path / "signed.tab")
    t = native.Tabula.create(
        path, "v",
        [native.Column("id"),
         native.Column("amt", type="SIGNED", signer="cfo")],
    )
    r = t.add_row("id", "1")
    t.set_signed(r, "amt", b"1000", sk)
    t.commit()
    t.close()

    t2 = native.Tabula.open(path)
    r2 = t2.search("id", "1")[0]
    assert t2.verify_signed(r2, "amt", pk) == b"1000"
    t2.close()


def test_keypair_wrong_public_key_fails_verification(tmp_path):
    sk, _pk = native.keypair()
    _sk2, pk2 = native.keypair()  # unrelated key
    path = str(tmp_path / "signed.tab")
    t = native.Tabula.create(
        path, "v",
        [native.Column("id"),
         native.Column("amt", type="SIGNED", signer="cfo")],
    )
    r = t.add_row("id", "1")
    t.set_signed(r, "amt", b"1000", sk)
    t.commit()
    t.close()

    t2 = native.Tabula.open(path)
    r2 = t2.search("id", "1")[0]
    with pytest.raises(native.TabulaError):
        t2.verify_signed(r2, "amt", pk2)
    t2.close()
