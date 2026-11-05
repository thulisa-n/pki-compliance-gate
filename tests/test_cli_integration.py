"""Real certificate fixtures through the neakam CLI.

These are the integration checks. CI regenerates the time-sensitive PEMs
before this module runs; ``sha1_cert.pem`` is the committed exception.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.support.neakam_cli import run

ROOT = Path(__file__).resolve().parents[1]
POLICY = "policies/cabf_policy.yaml"

# Exit codes match the historical compliance fixture matrix.
FIXTURES = [
    ("tests/certificates/valid_cert.pem", 0),
    ("tests/certificates/internal_domain_cert.pem", 2),
    ("tests/certificates/long_validity_cert.pem", 2),
    ("tests/certificates/no_san_cert.pem", 2),
    ("tests/certificates/weak_key_cert.pem", 3),
    ("tests/certificates/sha1_cert.pem", 3),
    ("tests/certificates/expired_cert.pem", 3),
    ("tests/certificates/ec_p192_cert.pem", 3),
]


@pytest.mark.integration
@pytest.mark.parametrize(
    ("fixture", "expected"),
    FIXTURES,
    ids=[Path(item[0]).name for item in FIXTURES],
)
def test_neakam_cli_exit_for_fixture(fixture: str, expected: int, tmp_path: Path) -> None:
    result = run(
        [
            "--cert",
            fixture,
            "--policy",
            POLICY,
            "--output",
            "json",
            "--report",
            str(tmp_path / "report.json"),
            "--evidence-dir",
            str(tmp_path / "evidence"),
        ],
        cwd=ROOT,
    )
    assert result.returncode == expected, result.stderr + result.stdout
    payload = json.loads(result.stdout)
    assert payload["certificate"] == fixture
    assert payload["report_schema_version"] == "2.0"
    assert result.stderr == ""


@pytest.mark.integration
def test_strict_profile_rejects_baseline_certificate(tmp_path: Path) -> None:
    result = run(
        [
            "--cert",
            "tests/certificates/valid_cert.pem",
            "--policy",
            "policies/profiles/crypto_agility_pqc_readiness.yaml",
            "--output",
            "json",
            "--report",
            str(tmp_path / "report.json"),
            "--evidence-dir",
            str(tmp_path / "evidence"),
        ],
        cwd=ROOT,
    )
    assert result.returncode != 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["compliant"] is False
    assert result.stderr == ""
