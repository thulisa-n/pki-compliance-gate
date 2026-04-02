from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace

from main import _exit_code_from_report


def test_exit_code_zero_for_compliant_fixture() -> None:
    process = subprocess.run(
        [sys.executable, "src/main.py", "--cert", "tests/certificates/valid_cert.pem"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0


def test_exit_code_three_for_critical_failure_fixture() -> None:
    process = subprocess.run(
        [sys.executable, "src/main.py", "--cert", "tests/certificates/sha1_cert.pem"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 3


def test_exit_code_non_zero_when_only_lint_fails() -> None:
    report = SimpleNamespace(checks=[], lint={"status": "fail"})
    assert _exit_code_from_report(report) == 2
