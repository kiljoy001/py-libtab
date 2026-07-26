"""Security-gate regression tests: bandit finds nothing.

Keeps the SAST gate green as part of the normal suite so a future
careless eval/subprocess/pickle/yaml.load on untrusted data is caught
immediately, not at some later audit. pip-audit is intentionally NOT
wired here — it hits the network and is a CI/release concern, run via
tests/security/check.sh.
"""

from __future__ import annotations

import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIBTAB = os.path.join(ROOT, "libtab")
BANDIT = os.path.join(ROOT, ".venv", "bin", "bandit")


@pytest.mark.skipif(not os.path.exists(BANDIT), reason="bandit not installed")
def test_bandit_reports_no_issues():
    proc = subprocess.run(
        [BANDIT, "-r", LIBTAB, "-q", "-f", "custom",
         "--msg-template", "{severity}:{test_id}:{line}:{msg}"],
        capture_output=True,
        text=True,
        check=False,
    )
    # bandit exits non-zero when it finds issues; -q suppresses the
    # scan-metrics banner so any stdout line is a real finding.
    findings = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert proc.returncode == 0 and not findings, (
        "bandit reported issues:\n" + "\n".join(findings)
    )
