from __future__ import annotations

import ssl
from pathlib import Path

from certguard.agents.api_tls_posture import ApiTlsPostureAgent


def test_apisec_agent_low_risk_for_valid_fixture(monkeypatch) -> None:
    pem = Path("tests/certificates/valid_cert.pem").read_text(encoding="utf-8")
    agent = ApiTlsPostureAgent()
    monkeypatch.setattr(
        agent,
        "_fetch_tls_posture",
        lambda host, port: {
            "certificate_pem": pem,
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
        },
    )

    result = agent.run({"endpoint": "https://api.example.com"})
    assert result.success is True
    assert result.data["risk_level"] == "LOW"
    assert result.data["tls_version"] == "TLSv1.3"


def test_apisec_agent_high_risk_for_sha1_fixture(monkeypatch) -> None:
    pem = Path("tests/certificates/sha1_cert.pem").read_text(encoding="utf-8")
    agent = ApiTlsPostureAgent()
    monkeypatch.setattr(
        agent,
        "_fetch_tls_posture",
        lambda host, port: {
            "certificate_pem": pem,
            "tls_version": "TLSv1.0",
            "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        },
    )

    result = agent.run({"endpoint": "https://api.example.com"})
    assert result.success is False
    assert result.data["risk_level"] == "HIGH"


def test_apisec_agent_medium_risk_for_weak_tls_posture(monkeypatch) -> None:
    pem = Path("tests/certificates/valid_cert.pem").read_text(encoding="utf-8")
    agent = ApiTlsPostureAgent()
    monkeypatch.setattr(
        agent,
        "_fetch_tls_posture",
        lambda host, port: {
            "certificate_pem": pem,
            "tls_version": "TLSv1.1",
            "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
        },
    )

    result = agent.run({"endpoint": "https://api.example.com"})
    assert result.success is False
    assert result.data["risk_level"] == "MEDIUM"


def test_apisec_context_enforces_tls_12_or_higher() -> None:
    context = ApiTlsPostureAgent()._build_ssl_context()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
