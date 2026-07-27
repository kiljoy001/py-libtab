"""Atheris fuzz harness: Tabula.open() on arbitrary .tab bytes.

This is the primary memory-safety target. A .tab file is untrusted input
(per docs/TABULA.md it crosses the network as a data envelope), and
open() feeds it straight into the C parser (ndbparse, schema parsing,
row-hash dedup, HASHED/SIGNED cell tag parsing). The Python-side guards
added elsewhere only cover the Python→C *argument* boundary; they do
nothing about a malformed *file* driving the C parser off the rails.

Run against the ASan build so a one-byte over-read becomes a located
crash, not silent corruption:

    LIBTAB_SO=$PWD/vendor/libtab-asan.so \
    LD_PRELOAD=$(gcc -print-file-name=libasan.so) \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    .venv/bin/python tests/fuzz/fuzz_open.py -atheris_runs=200000 \
        tests/fuzz/corpus_open

A TabulaError / UnicodeDecodeError / OSError is expected, valid
behavior on garbage input and is swallowed. Anything else — a segfault,
an ASan report, a hang — is a real finding.
"""

import os
import sys
import tempfile

import atheris

with atheris.instrument_imports():
    from libtab import native


def _one(data: bytes) -> None:
    # open() takes a path; write the fuzz buffer to a temp file first.
    fd, path = tempfile.mkstemp(suffix=".tab")
    try:
        os.write(fd, data)
        os.close(fd)
        try:
            t = native.Tabula.open(path)
        except (native.TabulaError, UnicodeDecodeError, OSError, ValueError):
            return  # expected rejections of malformed input
        # If it parsed, exercise the read paths too — those also touch C.
        # UnicodeDecodeError is expected here too: libtab cells are raw
        # bytes, and Tabula.get()/colname() decode as UTF-8, so a
        # non-UTF-8 cell legitimately raises it (a Python-layer API fact,
        # not a memory bug). Swallow it so the fuzzer keeps hunting for
        # actual C-level faults.
        try:
            for row in t.iter_rows():
                for i in range(t.ncolumns):
                    try:
                        col = t.colname(i)
                    except UnicodeDecodeError:
                        continue
                    if col:
                        try:
                            t.get(row, col)
                        except UnicodeDecodeError:
                            pass
        finally:
            t.close()
    finally:
        if os.path.exists(path):
            os.remove(path)


def main() -> None:
    atheris.Setup(sys.argv, _one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
