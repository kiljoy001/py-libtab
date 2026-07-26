#!/bin/bash
# run-all-tests.sh — the single automated entry point for every testing
# layer in py-libtab. See TESTING.md for what each layer does and why.
#
# Usage:
#   ./run-all-tests.sh                 # the standard gate (fast layers)
#   ./run-all-tests.sh all             # everything, including slow layers
#   ./run-all-tests.sh <layer>...      # only the named layers
#   ./run-all-tests.sh --list          # list layer names
#
# Layers:
#   build      (re)build vendor/libtab.so and libtab-asan.so
#   unit       pytest — unit + integration + crypto-vector + security-gate
#   coverage   pytest with line-coverage report
#   lint       ruff
#   dup        PMD/CPD copy-paste detection (source only)
#   sast       bandit static analysis
#   audit      pip-audit dependency advisories
#   fuzz       short atheris fuzz + ASan corpus replay (open + b64)
#   mutation   mutmut full run — the slow, thorough layer
#
# "standard" runs: unit lint dup sast audit  (+ build if the .so is missing)
# "all" runs every layer above.
#
# A missing OPTIONAL tool (pmd, atheris, gcc/libasan, mutmut) skips that
# layer with a warning rather than failing the run. A failing layer that
# CAN run makes the whole script exit non-zero.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$ROOT/.venv/bin"
VENDOR="$ROOT/vendor"
cd "$ROOT"

# ---- pretty output + result tracking -------------------------------------
GREEN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
declare -a RESULTS=()
FAILED=0

hdr()  { printf "\n${BOLD}=== %s ===${OFF}\n" "$1"; }
pass() { RESULTS+=("${GREEN}PASS${OFF}  $1"); }
skip() { RESULTS+=("${YEL}SKIP${OFF}  $1 ${YEL}($2)${OFF}"); printf "${YEL}skipping %s: %s${OFF}\n" "$1" "$2"; }
fail() { RESULTS+=("${RED}FAIL${OFF}  $1"); FAILED=1; }

have_bin() { command -v "$1" >/dev/null 2>&1; }
have_py()  { "$PY/python" -c "import $1" >/dev/null 2>&1; }

# ---- individual layers ---------------------------------------------------

layer_build() {
    hdr "build (vendor/libtab.so + libtab-asan.so)"
    if ! have_bin gcc; then skip build "gcc not found"; return; fi
    ( cd "$VENDOR" && ./build.sh >/dev/null 2>&1 ) \
        && ( cd "$VENDOR" && SANITIZE=1 ./build.sh >/dev/null 2>&1 ) \
        && { echo "built libtab.so + libtab-asan.so"; pass build; } \
        || fail build
}

ensure_built() {
    [ -f "$VENDOR/libtab.so" ] || layer_build
}

layer_unit() {
    hdr "unit + integration (pytest)"
    ensure_built
    if "$PY/pytest" -q; then pass unit; else fail unit; fi
}

layer_coverage() {
    hdr "coverage (pytest --cov)"
    ensure_built
    if ! have_py coverage; then skip coverage "pytest-cov not installed"; return; fi
    if "$PY/pytest" -q --cov=libtab --cov-report=term-missing; then pass coverage; else fail coverage; fi
}

layer_lint() {
    hdr "lint (ruff)"
    if ! [ -x "$PY/ruff" ]; then skip lint "ruff not installed"; return; fi
    if "$PY/ruff" check libtab tests; then pass lint; else fail lint; fi
}

layer_dup() {
    hdr "duplication (PMD / CPD)"
    if ! have_bin pmd; then skip dup "pmd not found"; return; fi
    # Source only; a small number of parallel-API clones is acceptable —
    # this reports, it does not fail the gate on cosmetic test duplication.
    local out
    out="$(pmd cpd --minimum-tokens 40 --language python --dir libtab --format text 2>/dev/null || true)"
    local n; n="$(printf '%s' "$out" | grep -c 'Found a' || true)"
    printf '%s\n' "$out"
    echo "source clone groups (min-40 tokens): $n"
    pass dup
}

layer_sast() {
    hdr "SAST (bandit)"
    if ! [ -x "$PY/bandit" ]; then skip sast "bandit not installed"; return; fi
    if "$PY/bandit" -r libtab -q; then pass sast; else fail sast; fi
}

layer_audit() {
    hdr "dependency audit (pip-audit)"
    if ! [ -x "$PY/pip-audit" ]; then skip audit "pip-audit not installed"; return; fi
    if "$PY/pip-audit" --skip-editable; then pass audit; else fail audit; fi
}

layer_fuzz() {
    hdr "fuzz (atheris) + ASan replay"
    if ! have_py atheris; then skip fuzz "atheris not installed"; return; fi
    ensure_built
    local ok=1
    for tgt in open b64; do
        echo "-- fuzz $tgt (short budget) --"
        "$ROOT/tests/fuzz/run.sh" fuzz "$tgt" -atheris_runs=20000 >/dev/null 2>&1 || ok=0
    done
    if [ -f "$VENDOR/libtab-asan.so" ] && have_bin gcc; then
        for tgt in open b64; do
            echo "-- ASan replay $tgt corpus --"
            local rep; rep="$("$ROOT/tests/fuzz/run.sh" replay "$tgt" 2>&1 || true)"
            if echo "$rep" | grep -qE "ERROR: AddressSanitizer|runtime error:"; then
                echo "$rep" | tail -30; ok=0
            fi
        done
    else
        echo "(ASan replay skipped — libtab-asan.so or gcc missing)"
    fi
    [ "$ok" = 1 ] && pass fuzz || fail fuzz
}

layer_mutation() {
    hdr "mutation (mutmut) — slow"
    if ! have_py mutmut; then skip mutation "mutmut not installed"; return; fi
    ensure_built
    # mutmut copies libtab/ + tests/ into mutants/ but not vendor/; the
    # tests resolve vendor/libtab.so relative to their own location, so a
    # symlink must exist inside the generated mutants/ tree. mutmut also
    # can't produce stats until that symlink is present, hence the two
    # invocations: generate (stats fails, ignored), symlink, real run.
    rm -rf mutants .mutmut-cache
    timeout 30 "$PY/mutmut" run --max-children 1 >/dev/null 2>&1 || true
    [ -d mutants ] && ln -sf ../vendor mutants/vendor
    "$PY/mutmut" run >/dev/null 2>&1 || true
    local counts; counts="$("$PY/mutmut" results --all true 2>/dev/null | grep -oE ': [a-z]+$' | sort | uniq -c)"
    echo "$counts"
    local survived; survived="$("$PY/mutmut" results --all true 2>/dev/null | grep -c ': survived' || true)"
    rm -rf mutants .mutmut-cache
    if [ "$survived" = "0" ]; then pass mutation; else echo "${RED}$survived mutants survived${OFF}"; fail mutation; fi
}

# ---- dispatch ------------------------------------------------------------

ALL_LAYERS=(build unit coverage lint dup sast audit fuzz mutation)
STANDARD=(unit lint dup sast audit)

if [ "${1:-}" = "--list" ]; then
    printf '%s\n' "${ALL_LAYERS[@]}"; exit 0
fi

case "${1:-standard}" in
    ""|standard) SELECTED=("${STANDARD[@]}") ;;
    all)         SELECTED=("${ALL_LAYERS[@]}") ;;
    *)           SELECTED=("$@") ;;
esac

for layer in "${SELECTED[@]}"; do
    if declare -f "layer_$layer" >/dev/null; then
        "layer_$layer"
    else
        echo "${RED}unknown layer: $layer${OFF} (see --list)"; FAILED=1
    fi
done

# ---- summary -------------------------------------------------------------
hdr "summary"
printf '%s\n' "${RESULTS[@]}"
if [ "$FAILED" = 0 ]; then
    printf "\n${GREEN}${BOLD}all selected layers passed${OFF}\n"; exit 0
else
    printf "\n${RED}${BOLD}one or more layers failed${OFF}\n"; exit 1
fi
