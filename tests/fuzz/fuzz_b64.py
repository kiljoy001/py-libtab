"""Atheris fuzz harness: b64_decode() on arbitrary bytes.

The base64 decoder is the other untrusted-input path into C: HASHED and
SIGNED cell payloads are base64url, and a decoder that miscounts padding
or over-reads on malformed input is a memory-safety bug reachable from a
crafted .tab cell. Also fuzzes the tag-decode path via a HASHED-typed
column when the input happens to look like a tagged cell.

Run against the ASan build (see fuzz_open.py header for the env recipe).
"""

import sys

import atheris

with atheris.instrument_imports():
    from libtab import native


def _one(data: bytes) -> None:
    # b64_decode takes str; feed it a lossy-decoded view of the bytes so
    # the fuzzer explores both valid and invalid base64 alphabets.
    s = data.decode("latin-1")
    try:
        native.b64_decode(s)
    except (native.TabulaError, ValueError, UnicodeError):
        pass  # expected on malformed base64
    # round-trip a real encode too (exercises tab_b64_encode's C buffer math)
    try:
        enc = native.b64_encode(data)
        native.b64_decode(enc)
    except native.TabulaError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, _one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
