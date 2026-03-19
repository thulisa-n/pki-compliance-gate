from __future__ import annotations

import subprocess
import sys


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
