"""Severity gate over pip-audit JSON. OSV is stubbed; the suite does not call it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.pip_audit_gate import (
    collect,
    cvss_v3_base_score,
    is_blocking,
    main,
    qualitative,
)


def test_cvss_v3_critical_vector_scores_9_8() -> None:
    score = cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8
    assert qualitative(score or 0) == "CRITICAL"


def test_incomplete_vector_is_ignored() -> None:
    assert cvss_v3_base_score("not-a-vector") is None
    assert cvss_v3_base_score("CVSS:3.1/AV:N") is None


@pytest.mark.parametrize(
    ("label", "blocks"),
    [("LOW", False), ("NONE", False), ("MEDIUM", True), ("MODERATE", True), ("HIGH", True), ("UNKNOWN", True)],
)
def test_blocking_labels(label: str, blocks: bool) -> None:
    assert is_blocking(label) is blocks


def _report(vuln_id: str = "CVE-2026-0001") -> dict:
    return {
        "dependencies": [
            {"name": "demo", "version": "1.0", "vulns": [{"id": vuln_id, "aliases": ["GHSA-demo"]}]}
        ]
    }


def test_low_advisory_does_not_fail() -> None:
    rows = collect(_report(), lambda _vuln_id: {"database_specific": {"severity": "LOW"}})
    assert rows[0]["blocking"] == "no"
    assert rows[0]["severity"] == "LOW"


def test_moderate_and_cvss_medium_fail() -> None:
    moderate = collect(_report(), lambda _vuln_id: {"database_specific": {"severity": "MODERATE"}})
    assert moderate[0]["blocking"] == "yes"
    medium = collect(
        _report(),
        lambda _vuln_id: {
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ]
        },
    )
    assert medium[0]["severity"] == "CRITICAL"
    assert medium[0]["blocking"] == "yes"


def test_missing_severity_fails_closed() -> None:
    rows = collect(_report(), lambda _vuln_id: {})
    assert rows[0]["severity"] == "UNKNOWN"
    assert rows[0]["blocking"] == "yes"


def test_clean_report_does_not_call_osv() -> None:
    called = {"n": 0}

    def lookup(_vuln_id: str) -> dict:
        called["n"] += 1
        return {}

    assert collect({"dependencies": [{"name": "pyyaml", "version": "6.0.3", "vulns": []}]}, lookup) == []
    assert called["n"] == 0


def test_cli_report_writes_a_table_and_exits(tmp_path: Path) -> None:
    report = tmp_path / "audit.json"
    report.write_text(json.dumps(_report()), encoding="utf-8")
    output = tmp_path / "table.txt"
    code = main(
        ["--report", str(report), "--output", str(output)],
        lookup=lambda _vuln_id: {"database_specific": {"severity": "LOW"}},
    )
    assert code == 0
    text = output.read_text(encoding="utf-8")
    assert "demo\t1.0\tCVE-2026-0001\tLOW\tno" in text

    code = main(
        ["--report", str(report)],
        lookup=lambda _vuln_id: {"database_specific": {"severity": "HIGH"}},
    )
    assert code == 1
