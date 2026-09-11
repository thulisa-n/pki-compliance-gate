from __future__ import annotations

import json
from pathlib import Path

from certguard.agents.trend_snapshot import TrendSnapshotAgent


def test_trend_snapshot_agent_writes_expected_counts(tmp_path: Path) -> None:
    report = {
        "certificate": "tests/certificates/valid_cert.pem",
        "compliant": True,
        "risk_level": "LOW",
        "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
        "coverage": {
            "controls_defined": 3,
            "controls_evaluated": 2,
            "passed": 2,
            "failed": 0,
            "waived": 0,
            "not_applicable": 1,
        },
        "checks": [
            {"name": "validity_days", "status": "pass"},
            {"name": "san_extension", "status": "pass"},
            {"name": "dcv_method", "status": "not_applicable"},
        ],
    }
    out = tmp_path / "trend.json"
    result = TrendSnapshotAgent().run(
        {"report": report, "output_path": str(out), "run_id": "123", "trigger": "schedule"}
    )

    assert result.success is True
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["counts"]["passed"] == 2
    assert payload["counts"]["failed"] == 0
    assert payload["counts"]["not_applicable"] == 1
    assert payload["run_id"] == "123"
    # The percentage score was removed in report schema 2.0.
    assert "score" not in payload
    assert payload["findings"]["critical"] == 0
    assert payload["coverage"]["controls_evaluated"] == 2
