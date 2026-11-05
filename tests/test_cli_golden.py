"""Golden CLI JSON and SARIF.

``--as-of`` pins the verdict, and the certificates below are not regenerated,
so a refactor that changes stdout fails this module. Refresh intentionally with
``UPDATE_GOLDENS=1 pytest tests/test_cli_golden.py``.
"""

from __future__ import annotations

import difflib
import os
from pathlib import Path

import pytest

from tests.support.neakam_cli import run

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden"
AS_OF = "2026-06-01"
POLICY = "policies/cabf_policy.yaml"

CASES = [
    ("tests/golden/frozen_valid.pem", 0, "frozen_valid"),
    ("tests/certificates/sha1_cert.pem", 3, "sha1_cert"),
]


def _assert_golden(name: str, actual: str) -> None:
    path = GOLDEN / name
    if os.environ.get("UPDATE_GOLDENS") == "1":
        path.write_text(actual, encoding="utf-8")
        return
    expected = path.read_text(encoding="utf-8")
    if actual == expected:
        return
    diff = "".join(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=name,
            tofile="actual",
        )
    )
    raise AssertionError(f"golden mismatch for {name}\n{diff[:4000]}")


@pytest.mark.parametrize(
    ("certificate", "expected_exit", "stem"),
    CASES,
    ids=[item[2] for item in CASES],
)
@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_cli_stdout_matches_golden(
    certificate: str, expected_exit: int, stem: str, fmt: str, tmp_path: Path
) -> None:
    result = run(
        [
            "--cert",
            certificate,
            "--policy",
            POLICY,
            "--as-of",
            AS_OF,
            "--output",
            fmt,
            "--report",
            str(tmp_path / "report.json"),
            "--evidence-dir",
            str(tmp_path / "evidence"),
        ],
        cwd=ROOT,
    )
    assert result.returncode == expected_exit, result.stderr + result.stdout
    assert result.stderr == ""
    suffix = "json" if fmt == "json" else "sarif.json"
    _assert_golden(f"{stem}.{suffix}", result.stdout)
