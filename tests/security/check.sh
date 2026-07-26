#!/bin/bash
# Run the static/supply-chain security gates for py-libtab.
#
# These complement the dynamic layers (fuzzing + ASan replay in
# tests/fuzz/, crypto known-answer vectors in tests/test_crypto_vectors.py):
#
#   bandit    — Python SAST. Expected to find nothing here (no eval,
#               shell, pickle, or yaml.load on untrusted data); kept as a
#               cheap regression gate so a future careless one gets caught.
#   pip-audit — supply-chain advisories for installed deps. Near-no-op
#               today (zero runtime deps — pure ctypes), but the gate
#               belongs in CI for when packaging/argon2-cffi land.
#
# Exits non-zero if either gate reports an issue.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PY="$ROOT/.venv/bin"

echo "=== bandit (Python SAST) ==="
"$PY/bandit" -r "$ROOT/libtab" -q
echo "bandit: clean"
echo

echo "=== pip-audit (dependency advisories) ==="
# --skip-editable avoids auditing this package itself (not on PyPI).
"$PY/pip-audit" --skip-editable
echo "pip-audit: clean"
