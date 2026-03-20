from __future__ import annotations

from pathlib import Path

from certguard.agents.api_tls_posture import ApiTlsPostureAgent


def test_apisec_agent_low_risk_for_valid_fixture(monkeypatch) -> None:
    pem = Path("tests/certificates/valid_cert.pem").read_text(encoding="utf-8")
    agent = ApiTlsPostureAgent()
    monkeypatch.setattr(agent, "_fetch_certificate_pem", lambda host, port: pem)

    result = agent.run({"endpoint": "https://api.example.com"})
    assert result.success is True
    assert result.data["risk_level"] == "LOW"


def test_apisec_agent_high_risk_for_sha1_fixture(monkeypatch) -> None:
    pem = Path("tests/certificates/sha1_cert.pem").read_text(encoding="utf-8")
    agent = ApiTlsPostureAgent()
    monkeypatch.setattr(agent, "_fetch_certificate_pem", lambda host, port: pem)

    result = agent.run({"endpoint": "https://api.example.com"})
    assert result.success is False
    assert result.data["risk_level"] == "HIGH"
