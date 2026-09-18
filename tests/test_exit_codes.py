from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path

from certguard.cli import _exit_code_from_report


def test_exit_code_zero_for_compliant_fixture(tmp_path: Path) -> None:
    report_file = tmp_path / "report.json"
    evidence_dir = tmp_path / "evidence"
    process = subprocess.run(
        [
            sys.executable,
            "src/main.py",
            "--cert",
            "tests/certificates/valid_cert.pem",
            "--report",
            str(report_file),
            "--evidence-dir",
            str(evidence_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0


def test_exit_code_three_for_critical_failure_fixture(tmp_path: Path) -> None:
    report_file = tmp_path / "report.json"
    evidence_dir = tmp_path / "evidence"
    process = subprocess.run(
        [
            sys.executable,
            "src/main.py",
            "--cert",
            "tests/certificates/sha1_cert.pem",
            "--report",
            str(report_file),
            "--evidence-dir",
            str(evidence_dir),
        ],
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
    assert "ERROR: evaluate requires --cert or --csr." in process.stderr


def test_cli_returns_usage_error_when_cert_and_csr_both_set() -> None:
    process = subprocess.run(
        [
            sys.executable,
            "src/main.py",
            "--cert",
            "tests/certificates/valid_cert.pem",
            "--csr",
            "tests/certificates/csrs/valid.csr",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 2
    assert "exactly one of --cert or --csr" in process.stderr


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
