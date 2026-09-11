"""Readiness against the dated CA/Browser Forum validity schedule.

This is the free-tier answer to "do we have a 2027 problem?". A team should be
able to find that out without paying anyone, so it lives in the core.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import pytest
import yaml

from certguard.agents.x509_parser import X509ParserAgent
from certguard.policy import load_policy
from certguard.readiness import (
    ACTION_NEEDED,
    READY,
    UNKNOWN,
    assess_readiness,
    load_baseline,
    readiness_exit_code,
    render_readiness_markdown,
    render_readiness_text,
)

POLICY_PATH = Path("policies/cabf_policy.yaml")
BASELINE_PATH = Path("policies/standards_baseline.yaml")


@pytest.fixture
def policy() -> dict:
    return load_policy(POLICY_PATH)


@pytest.fixture
def baseline() -> dict:
    return load_baseline(BASELINE_PATH)


def test_phase_in_force_is_satisfied_today(policy: dict, baseline: dict) -> None:
    result = assess_readiness(policy, baseline, as_of="2026-09-11")
    in_force = next(p for p in result["phases"] if p["position"] == "in_force")

    assert in_force["max_validity_days"] == 200
    assert in_force["status"] == READY


def test_future_phases_are_surfaced_with_a_countdown(
    policy: dict, baseline: dict
) -> None:
    result = assess_readiness(policy, baseline, as_of="2026-09-11")
    positions = {p["position"]: p for p in result["phases"]}

    assert positions["next"]["effective"] == "2027-03-15"
    assert positions["next"]["status"] == ACTION_NEEDED
    assert positions["next"]["days_until_effective"] == 185
    assert positions["future"]["max_validity_days"] == 47


def test_superseded_phases_are_not_reported(policy: dict, baseline: dict) -> None:
    """The 398-day phase is history, not a target."""
    result = assess_readiness(policy, baseline, as_of="2026-09-11")

    assert all(p["effective"] != "2020-09-01" for p in result["phases"])


def test_required_changes_name_field_target_and_deadline(
    policy: dict, baseline: dict
) -> None:
    result = assess_readiness(policy, baseline, as_of="2026-09-11")
    change = next(
        c
        for c in result["required_changes"]
        if c["field"] == "certificate.max_validity_days" and c["required"] == 100
    )

    assert change["current"] == 200
    assert change["effective"] == "2027-03-15"
    assert change["days_remaining"] == 185


def test_dcv_reuse_gap_appears_for_the_2029_phase(
    policy: dict, baseline: dict
) -> None:
    result = assess_readiness(policy, baseline, as_of="2026-09-11")
    fields = {(c["field"], c["required"]) for c in result["required_changes"]}

    assert ("dcv.max_age_days", 10) in fields


def test_a_fully_tightened_policy_is_ready(policy: dict, baseline: dict) -> None:
    strict = dict(policy)
    strict["certificate"] = {**policy["certificate"], "max_validity_days": 47}
    strict["dcv"] = {**policy["dcv"], "max_age_days": 10}

    result = assess_readiness(strict, baseline, as_of="2026-09-11")

    assert result["overall_status"] == READY
    assert result["required_changes"] == []
    assert all(p["status"] == READY for p in result["phases"])


def test_breaching_the_phase_in_force_is_present_tense(
    policy: dict, baseline: dict
) -> None:
    """A 200-day policy is fine today and non-compliant from 2027-03-15."""
    result = assess_readiness(policy, baseline, as_of="2027-04-01")
    in_force = next(p for p in result["phases"] if p["position"] == "in_force")

    assert in_force["effective"] == "2027-03-15"
    assert in_force["status"] == ACTION_NEEDED


def test_exit_codes_distinguish_a_plan_from_a_breach(
    policy: dict, baseline: dict
) -> None:
    future_gap = assess_readiness(policy, baseline, as_of="2026-09-11")
    breach = assess_readiness(policy, baseline, as_of="2027-04-01")

    strict = dict(policy)
    strict["certificate"] = {**policy["certificate"], "max_validity_days": 47}
    strict["dcv"] = {**policy["dcv"], "max_age_days": 10}
    ready = assess_readiness(strict, baseline, as_of="2026-09-11")

    assert readiness_exit_code(ready) == 0
    assert readiness_exit_code(future_gap) == 1
    assert readiness_exit_code(breach) == 2


def test_certificate_validity_is_assessed_when_supplied(
    policy: dict, baseline: dict, make_cert: Callable[..., Path]
) -> None:
    cert = make_cert(validity_days=500)
    parser_data = X509ParserAgent().run({"cert_path": str(cert)}).data

    result = assess_readiness(
        policy, baseline, as_of="2026-09-11", parser_data=parser_data
    )

    assert result["certificate_validity_days"] == 500
    cert_gaps = [
        c for c in result["required_changes"] if "evaluated certificate" in c["field"]
    ]
    assert cert_gaps, "a 500-day certificate must be flagged against every phase"
    in_force = next(p for p in result["phases"] if p["position"] == "in_force")
    assert in_force["status"] == ACTION_NEEDED


def test_a_short_certificate_passes_every_phase(
    policy: dict, baseline: dict, make_cert: Callable[..., Path]
) -> None:
    cert = make_cert(validity_days=30)
    parser_data = X509ParserAgent().run({"cert_path": str(cert)}).data

    result = assess_readiness(
        policy, baseline, as_of="2026-09-11", parser_data=parser_data
    )
    cert_gaps = [
        c for c in result["required_changes"] if "evaluated certificate" in c["field"]
    ]
    assert cert_gaps == []


def test_missing_schedule_is_reported_as_unknown(policy: dict) -> None:
    result = assess_readiness(policy, {"baseline": {}}, as_of="2026-09-11")

    assert result["overall_status"] == UNKNOWN
    assert result["phases"] == []
    assert "no dated schedule" in result["detail"]
    assert readiness_exit_code(result) == 2


def test_text_render_is_readable(policy: dict, baseline: dict) -> None:
    text = render_readiness_text(
        assess_readiness(policy, baseline, as_of="2026-09-11")
    )

    assert "CertGuard validity readiness" in text
    assert "Ballot SC-081v3" in text
    assert "ACTION NEEDED" in text
    assert "2027-03-15" in text


def test_markdown_render_is_a_table(policy: dict, baseline: dict) -> None:
    markdown = render_readiness_markdown(
        assess_readiness(policy, baseline, as_of="2026-09-11")
    )

    assert markdown.startswith("## CertGuard validity readiness")
    assert "| Phase | Effective |" in markdown
    assert "### Required changes" in markdown


def test_required_changes_are_deduplicated_in_output(
    policy: dict, baseline: dict
) -> None:
    text = render_readiness_text(
        assess_readiness(policy, baseline, as_of="2026-09-11")
    )
    lines = [line for line in text.splitlines() if "-> 100" in line]

    assert len(lines) == 1


def test_load_baseline_rejects_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_baseline(tmp_path / "nope.yaml")


def test_load_baseline_rejects_a_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(["not", "a", "mapping"]), encoding="utf-8")

    with pytest.raises(ValueError, match="must be a YAML object"):
        load_baseline(path)


def test_cli_readiness_mode_writes_json(tmp_path: Path) -> None:
    import subprocess
    import sys

    out = tmp_path / "readiness.json"
    process = subprocess.run(
        [
            sys.executable, "src/main.py",
            "--mode", "readiness",
            "--as-of", "2026-09-11",
            "--readiness-output", str(out),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert process.returncode == 1, "a future-phase gap is a plan, not a failure"
    assert out.is_file()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["baseline_authority"] == "Ballot SC-081v3"
    assert payload["overall_status"] == ACTION_NEEDED
