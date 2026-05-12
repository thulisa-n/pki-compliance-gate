from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path

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


def test_cli_returns_usage_error_code_when_cert_missing() -> None:
    process = subprocess.run(
        [sys.executable, "src/main.py", "--mode", "evaluate"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 2
    assert "ERROR: --cert is required in evaluate mode." in process.stderr


def test_cli_returns_error_code_for_invalid_json_input(tmp_path: Path) -> None:
    bad_report = tmp_path / "bad-report.json"
    bad_report.write_text("{not-json", encoding="utf-8")
    process = subprocess.run(
        [
            sys.executable,
            "src/main.py",
            "--mode",
            "summary",
            "--report-input",
            str(bad_report),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 2
    assert "Invalid JSON" in process.stderr
