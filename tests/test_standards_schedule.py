"""Dated standards schedule and upcoming-change readiness.

Regression tests for the defect where `scripts/sync_cabf_baseline.py` scraped
BR.md for "N-day" strings and hard-preferred 200:

    if 200 in values: return 200

The string "200-day" survives in the ballot's own schedule table, so the
scraper would have kept asserting a 200-day maximum through the reduction to
100 days on 2027-03-15 and to 47 days on 2029-03-15 -- the drift detector would
have reported success across the exact change it exists to catch.

The baseline is now a hand-maintained dated schedule, the sync script only
detects that the upstream document changed, and the watch agent compares
against the phase in force plus the next one.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from certguard.agents.standards_watch import StandardsWatchAgent
from certguard.policy import load_policy

BASELINE_PATH = Path("policies/standards_baseline.yaml")
POLICY_PATH = Path("policies/cabf_policy.yaml")


@pytest.fixture
def baseline() -> dict:
    return yaml.safe_load(BASELINE_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def policy() -> dict:
    return load_policy(POLICY_PATH)


def _run(policy: dict, baseline: dict, as_of: str):
    return StandardsWatchAgent().run(
        {"policy": policy, "baseline": baseline, "as_of": as_of}
    )


def test_baseline_encodes_the_sc081v3_schedule(baseline: dict) -> None:
    schedule = {
        entry["effective"]: (entry["max_validity_days"], entry["dcv_reuse_days"])
        for entry in baseline["schedule"]
    }

    assert schedule["2026-03-15"] == (200, 200)
    assert schedule["2027-03-15"] == (100, 100)
    assert schedule["2029-03-15"] == (47, 10)


def test_active_phase_resolves_by_date(policy: dict, baseline: dict) -> None:
    result = _run(policy, baseline, "2026-09-11")
    assert result.data["active_phase"]["max_validity_days"] == 200

    result = _run(policy, baseline, "2027-06-01")
    assert result.data["active_phase"]["max_validity_days"] == 100

    result = _run(policy, baseline, "2029-06-01")
    assert result.data["active_phase"]["max_validity_days"] == 47


def test_policy_aligned_today(policy: dict, baseline: dict) -> None:
    result = _run(policy, baseline, "2026-09-11")

    assert result.success is True
    assert result.data["drift_count"] == 0


def test_upcoming_tightening_is_surfaced_before_it_lands(
    policy: dict, baseline: dict
) -> None:
    """The feature the old scraper could not provide."""
    result = _run(policy, baseline, "2026-09-11")
    gaps = result.data["readiness_gaps"]

    assert result.data["readiness_gap_count"] == 1
    gap = gaps[0]
    assert gap["field"] == "certificate.max_validity_days"
    assert gap["current"] == 200
    assert gap["required"] == 100
    assert gap["effective"] == "2027-03-15"
    assert gap["days_remaining"] > 0
    readiness = next(
        c for c in result.checks if c.name == "upcoming_standards_readiness"
    )
    assert readiness.status == "fail"


def test_drift_detected_once_the_2027_phase_is_in_force(
    policy: dict, baseline: dict
) -> None:
    """The exact case the previous implementation reported as aligned."""
    result = _run(policy, baseline, "2027-04-01")

    assert result.success is False
    drift_fields = {item["field"] for item in result.data["drifts"]}
    assert "max_validity_days" in drift_fields
    check = next(c for c in result.checks if c.name == "max_validity_days_alignment")
    assert check.status == "fail"
    assert "exceeds the standard maximum of 100" in check.details


def test_dcv_reuse_drift_detected_in_2029(policy: dict, baseline: dict) -> None:
    result = _run(policy, baseline, "2029-04-01")

    drift_fields = {item["field"] for item in result.data["drifts"]}
    assert "max_validity_days" in drift_fields
    assert "dcv_reuse_days" in drift_fields


def test_stricter_policy_is_not_drift(policy: dict, baseline: dict) -> None:
    """Only a more permissive policy is drift."""
    strict = dict(policy)
    strict["certificate"] = {**policy["certificate"], "max_validity_days": 47}
    strict["dcv"] = {**policy["dcv"], "max_age_days": 7}

    result = _run(strict, baseline, "2026-09-11")

    assert result.success is True
    assert result.data["readiness_gap_count"] == 0


def test_prohibited_algorithms_must_be_a_superset(
    policy: dict, baseline: dict
) -> None:
    permissive = dict(policy)
    permissive["signature"] = {"prohibited_algorithms": ["md5"]}

    result = _run(permissive, baseline, "2026-09-11")

    assert result.success is False
    check = next(
        c for c in result.checks if c.name == "prohibited_algorithms_alignment"
    )
    assert check.status == "fail"
    assert "sha1" in check.details


def test_non_baseline_curve_is_drift(policy: dict, baseline: dict) -> None:
    permissive = dict(policy)
    permissive["key"] = {**policy["key"], "allowed_ec_curves": ["secp192r1"]}

    result = _run(permissive, baseline, "2026-09-11")

    assert result.success is False
    check = next(c for c in result.checks if c.name == "allowed_ec_curves_alignment")
    assert check.status == "fail"


def test_baseline_terms_are_populated(baseline: dict) -> None:
    """The sync script previously overwrote this file and emptied the list."""
    ids = {term["id"] for term in baseline["terms"]}

    assert len(ids) >= 5
    assert "CABF-BR-6.1.5" in ids
    assert "RFC-5280-4.1.2.5" in ids


def test_missing_schedule_is_reported_not_silently_ignored(policy: dict) -> None:
    result = _run(policy, {"baseline": {}, "expected": {}}, "2026-09-11")

    assert result.success is False
    check = next(
        c for c in result.checks if c.name == "standards_schedule_available"
    )
    assert check.status == "fail"
