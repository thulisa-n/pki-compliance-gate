"""Guard against committed certificate fixtures silently expiring.

Every fixture was originally minted with notBefore 2026-03-16. By September
2026 five of six had expired, including ``valid_cert.pem``, which the CI matrix
asserts exits 0. Nothing failed, because until report schema 2.0 nothing
compared notAfter to the evaluation time.

This test turns that silent rot into a loud, actionable failure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.support.certificates import (
    INTENTIONALLY_EXPIRED_FIXTURES,
    fixture_expiry_report,
)

FIXTURES_DIR = Path("tests/certificates")
MIN_REMAINING_DAYS = 30


def test_fixture_directory_is_populated() -> None:
    assert sorted(p.name for p in FIXTURES_DIR.glob("*.pem"))


@pytest.mark.parametrize("entry", fixture_expiry_report(FIXTURES_DIR), ids=lambda e: e["name"])
def test_fixture_is_not_expiring(entry: dict) -> None:
    if entry["intentionally_expired"]:
        assert entry["expired"], (
            f"{entry['name']} is listed as intentionally expired but is still valid; "
            "update INTENTIONALLY_EXPIRED_FIXTURES."
        )
        return

    assert not entry["expired"], (
        f"{entry['name']} expired on {entry['not_after'].date()}. "
        "Regenerate with: python scripts/generate_test_certificates.py"
    )
    assert int(entry["days_until_expiry"]) >= MIN_REMAINING_DAYS, (
        f"{entry['name']} expires in {entry['days_until_expiry']} days, under the "
        f"{MIN_REMAINING_DAYS}-day floor. "
        "Regenerate with: python scripts/generate_test_certificates.py"
    )


def test_intentionally_expired_set_is_documented() -> None:
    names = {p.name for p in FIXTURES_DIR.glob("*.pem")}
    assert INTENTIONALLY_EXPIRED_FIXTURES <= names


def test_expired_fixture_exists_for_regression_coverage() -> None:
    """The expiry false negative needs a permanent artefact."""
    assert (FIXTURES_DIR / "expired_cert.pem").is_file()


def test_p192_fixture_exists_for_regression_coverage() -> None:
    """The EC false negative needs a permanent artefact."""
    assert (FIXTURES_DIR / "ec_p192_cert.pem").is_file()
