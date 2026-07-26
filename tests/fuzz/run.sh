#!/bin/bash
# Two-phase fuzzing of libtab's untrusted-input C paths.
#
#   tests/fuzz/run.sh fuzz  open|b64  [atheris args...]
#       Coverage-guided fuzzing against the NORMAL -O2 build. Fast and
#       stable; grows the on-disk corpus with any input reaching new
#       code, and reports Python-level crashes/hangs. Defaults to a
#       short bounded run (-atheris_runs=50000). Pass e.g.
#       -max_total_time=600 for a real campaign.
#
#   tests/fuzz/run.sh replay  open|b64
#       Re-run EVERY corpus input through the ASan+UBSan build (no
#       libFuzzer), so a memory bug on any fuzzer-discovered input
#       surfaces as a located ASan report. This is the memory-safety
#       gate. Kept separate from fuzzing because atheris's bundled
#       libFuzzer and ASan fight over coverage/signal handling when
#       preloaded together (produces spurious non-reproducible
#       "deadly signal" reports) — replaying the corpus under ASan
#       without libFuzzer active avoids that entirely.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# Prefer the repo venv; fall back to python3 on PATH (e.g. when this
# script is invoked from a copied tree such as mutmut's mutants/ dir,
# where $ROOT/.venv does not exist).
VENV="$ROOT/.venv/bin/python"
[ -x "$VENV" ] || VENV="$(command -v python3)"
NORMAL_SO="$ROOT/vendor/libtab.so"
ASAN_SO="$ROOT/vendor/libtab-asan.so"

mode="${1:-fuzz}"; shift || true
target="${1:-open}"; shift || true
case "$target" in
    open) harness="$HERE/fuzz_open.py"; corpus="$HERE/corpus_open" ;;
    b64)  harness="$HERE/fuzz_b64.py";  corpus="$HERE/corpus_b64"  ;;
    seal) harness="$HERE/fuzz_seal.py"; corpus="$HERE/corpus_seal" ;;
    *) echo "unknown target: $target (use 'open', 'b64', or 'seal')" >&2; exit 2 ;;
esac

case "$mode" in
fuzz)
    [ -f "$NORMAL_SO" ] || { echo "missing $NORMAL_SO — (cd vendor && ./build.sh)" >&2; exit 1; }
    if [ "$#" -eq 0 ]; then set -- -atheris_runs=50000; fi
    exec env LIBTAB_SO="$NORMAL_SO" "$VENV" "$harness" "$@" "$corpus"
    ;;
replay)
    [ -f "$ASAN_SO" ] || { echo "missing $ASAN_SO — (cd vendor && SANITIZE=1 ./build.sh)" >&2; exit 1; }
    ASAN_RT="$(gcc -print-file-name=libasan.so)"
    # -runs=0 tells libFuzzer to execute each named corpus file once and
    # exit, without generating new inputs (so no libFuzzer/ASan conflict).
    exec env \
        LIBTAB_SO="$ASAN_SO" \
        LD_PRELOAD="$ASAN_RT" \
        ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:handle_segv=1" \
        UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
        "$VENV" "$harness" -runs=0 "$corpus"/*
    ;;
*)
    echo "unknown mode: $mode (use 'fuzz' or 'replay')" >&2; exit 2 ;;
esac
