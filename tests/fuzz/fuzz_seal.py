"""Atheris fuzz harness: unseal() on arbitrary bytes.

A sealed blob comes off disk / the wire as untrusted input, and unseal()
parses it (nonce/mac/ciphertext split) before handing it to the AEAD.
A decoder that mis-slices a short or malformed blob is a memory-safety
bug reachable from a crafted cell. Run against the ASan build (see
fuzz_open.py header for the env recipe).
"""

import sys

import atheris

with atheris.instrument_imports():
    from libtab import native

_KEY = bytes(range(32))


def _one(data: bytes) -> None:
    # unseal a fuzzed blob under a fixed key — nearly all inputs are
    # forged/malformed and must raise cleanly, never crash.
    try:
        native.unseal(_KEY, data)
    except native.TabulaError:
        pass
    # also fuzz the seal→unseal round-trip (exercises the AEAD buffers)
    try:
        native.unseal(_KEY, native.seal(_KEY, data))
    except native.TabulaError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, _one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
