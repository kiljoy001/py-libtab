"""Smoke test: a short fuzz + ASan replay runs clean.

Not a full campaign — a bounded budget that (a) proves the fuzz harness
and the sanitizer build still work end-to-end, and (b) catches a
regression that makes open()/b64_decode crash on easily-reached input.
For real fuzzing, run tests/fuzz/run.sh with a large budget.

Skips if atheris isn't installed or the ASan build isn't present.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RUN = os.path.join(HERE, "fuzz", "run.sh")
ASAN_SO = os.path.join(ROOT, "vendor", "libtab-asan.so")
NORMAL_SO = os.path.join(ROOT, "vendor", "libtab.so")

atheris_missing = (
    subprocess.run(
        [sys.executable, "-c", "import atheris"], capture_output=True, check=False
    ).returncode
    != 0
)

# These shell out to run.sh with the real venv + built .so; they are
# integration checks of the fuzz tooling, not unit tests of native.py.
# Under mutmut the suite runs from a copied mutants/ tree with no venv
# or built libraries, so skip there — mutation coverage of native.py
# comes from the in-process unit tests, not this subprocess harness.
_IN_MUTANTS_COPY = os.sep + "mutants" + os.sep in os.path.abspath(__file__)

pytestmark = [
    pytest.mark.skipif(atheris_missing, reason="atheris not installed"),
    pytest.mark.skipif(not os.path.exists(NORMAL_SO), reason="vendor/libtab.so not built"),
    pytest.mark.skipif(_IN_MUTANTS_COPY, reason="integration harness; not run under mutmut"),
]


@pytest.mark.parametrize("target", ["open", "b64", "seal"])
def test_short_fuzz_runs_clean(target, tmp_path):
    """A few thousand runs against the normal build must exit 0 (no
    escaped exception, no crash) on the seed corpus."""
    proc = subprocess.run(
        ["bash", RUN, "fuzz", target, "-atheris_runs=3000"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(tmp_path),  # any crash-* artifact lands here, not the repo
        check=False,
    )
    assert proc.returncode == 0, (
        f"fuzz {target} exited {proc.returncode}\n"
        f"stdout:\n{proc.stdout[-2000:]}\nstderr:\n{proc.stderr[-2000:]}"
    )
    # a crash artifact would be written on failure; assert none appeared
    assert not any(p.name.startswith("crash-") for p in tmp_path.iterdir())


@pytest.mark.skipif(not os.path.exists(ASAN_SO), reason="vendor/libtab-asan.so not built")
@pytest.mark.parametrize("target", ["open", "b64", "seal"])
def test_asan_replay_of_corpus_clean(target):
    """Replaying the checked-in seed corpus through the ASan build must
    produce no sanitizer report."""
    proc = subprocess.run(
        ["bash", RUN, "replay", target],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"ASan replay {target} failed:\n{combined[-3000:]}"
    assert "ERROR: AddressSanitizer" not in combined, combined[-3000:]
    assert "runtime error:" not in combined, combined[-3000:]  # UBSan
