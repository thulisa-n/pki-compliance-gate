from __future__ import annotations

from certguard.agents.external_signal_watch import ExternalSignalWatchAgent


def test_external_signal_watch_generates_recommendations() -> None:
    signals = [
        {
            "id": "s1",
            "title": "Lifecycle shift",
            "category": "certificate_lifecycle",
            "priority": "high",
        },
        {
            "id": "s2",
            "title": "Crypto readiness",
            "category": "crypto_transition",
            "priority": "high",
        },
    ]
    result = ExternalSignalWatchAgent().run({"signals": signals})
    assert result.success is True
    assert result.data["signal_count"] == 2
    assert result.data["recommendation_count"] == 2
    controls = {item["control"] for item in result.data["recommendations"]}
    assert "max_validity_days" in controls
    assert "crypto_transition_readiness" in controls
