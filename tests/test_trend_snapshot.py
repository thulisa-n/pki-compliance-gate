from __future__ import annotations

import json
from pathlib import Path

from certguard.agents.trend_snapshot import TrendSnapshotAgent


def test_trend_snapshot_agent_writes_expected_counts(tmp_path: Path) -> None:
    report = {
        "certificate": "tests/certificates/valid_cert.pem",
        "compliant": True,
        "score": 100.0,
        "risk_level": "LOW",
        "checks": [
            {"name": "validity_days", "status": "pass"},
            {"name": "san_extension", "status": "pass"},
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
    assert payload["run_id"] == "123"
