from __future__ import annotations

import ssl
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import certguard.agents.api_tls_posture as api_tls_module
from certguard.agents.api_tls_posture import ApiTlsPostureAgent


def test_apisec_agent_low_risk_for_valid_fixture(monkeypatch) -> None:
    pem = Path("tests/certificates/valid_cert.pem").read_text(encoding="utf-8")
    cert = api_tls_module.x509.load_pem_x509_certificate(pem.encode("utf-8"))
    fixed_now = cert.not_valid_after_utc - timedelta(days=60)

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            if tz is None:
                return fixed_now.replace(tzinfo=None)
            return fixed_now.astimezone(tz)

    agent = ApiTlsPostureAgent()
    monkeypatch.setattr(api_tls_module, "datetime", FrozenDateTime)
    monkeypatch.setattr(
        agent,
        "_fetch_tls_posture",
        lambda host, port, **_: {
            "certificate_pem": pem,
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
        },
    )

    result = agent.run({"endpoint": "https://api.example.com", "allow_network": True})
    assert result.success is True
    assert result.data["risk_level"] == "LOW"
    assert result.data["tls_version"] == "TLSv1.3"


def test_apisec_agent_expiring_fixture_is_expected_to_fail(monkeypatch) -> None:
    pem = Path("tests/certificates/valid_cert.pem").read_text(encoding="utf-8")
    cert = api_tls_module.x509.load_pem_x509_certificate(pem.encode("utf-8"))
    fixed_now = cert.not_valid_after_utc - timedelta(days=10)

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            if tz is None:
                return fixed_now.replace(tzinfo=None)
            return fixed_now.astimezone(tz)

    agent = ApiTlsPostureAgent()
    monkeypatch.setattr(api_tls_module, "datetime", FrozenDateTime)
    monkeypatch.setattr(
        agent,
        "_fetch_tls_posture",
        lambda host, port, **_: {
            "certificate_pem": pem,
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
        },
    )

    result = agent.run({"endpoint": "https://api.example.com", "allow_network": True})
    assert result.success is False
    assert result.data["risk_level"] == "MEDIUM"
    expiry_check = next(
        check for check in result.checks if check.name == "endpoint_certificate_expiry"
    )
    assert expiry_check.status == "fail"


def test_apisec_agent_high_risk_for_sha1_fixture(monkeypatch) -> None:
    pem = Path("tests/certificates/sha1_cert.pem").read_text(encoding="utf-8")
    agent = ApiTlsPostureAgent()
    monkeypatch.setattr(
        agent,
        "_fetch_tls_posture",
        lambda host, port, **_: {
            "certificate_pem": pem,
            "tls_version": "TLSv1.0",
            "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        },
    )

    result = agent.run({"endpoint": "https://api.example.com", "allow_network": True})
    assert result.success is False
    assert result.data["risk_level"] == "HIGH"


def test_apisec_agent_medium_risk_for_weak_tls_posture(monkeypatch) -> None:
    pem = Path("tests/certificates/valid_cert.pem").read_text(encoding="utf-8")
    agent = ApiTlsPostureAgent()
    monkeypatch.setattr(
        agent,
        "_fetch_tls_posture",
        lambda host, port, **_: {
            "certificate_pem": pem,
            "tls_version": "TLSv1.1",
            "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
        },
    )

    result = agent.run({"endpoint": "https://api.example.com", "allow_network": True})
    assert result.success is False
    assert result.data["risk_level"] == "MEDIUM"


def test_apisec_context_enforces_tls_12_or_higher() -> None:
    context = ApiTlsPostureAgent()._build_ssl_context()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_apisec_agent_returns_structured_error_for_invalid_pem(monkeypatch) -> None:
    agent = ApiTlsPostureAgent()
    monkeypatch.setattr(
        agent,
        "_fetch_tls_posture",
        lambda host, port, **_: {
            "certificate_pem": "not-a-pem",
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
        },
    )
    result = agent.run({"endpoint": "https://api.example.com", "allow_network": True})
    assert result.success is False
    assert result.errors
    assert "Failed to evaluate endpoint TLS posture" in result.errors[0]


def test_apisec_refuses_network_without_opt_in(monkeypatch) -> None:
    agent = ApiTlsPostureAgent()

    def boom(host: str, port: int, *, timeout: float = 10) -> dict[str, str]:
        raise AssertionError(f"network {host}:{port} timeout={timeout}")

    monkeypatch.setattr(agent, "_fetch_tls_posture", boom)
    result = agent.run({"endpoint": "https://api.example.com"})
    assert result.success is False
    assert result.errors
    assert "--allow-network" in result.errors[0]


def test_fetch_uses_timeout_and_stays_on_the_listed_host(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_connection(address: tuple[str, int], timeout: float | None = None):
        seen["address"] = address
        seen["timeout"] = timeout
        raise OSError("stop")

    monkeypatch.setattr(api_tls_module.socket, "create_connection", fake_connection)
    result = ApiTlsPostureAgent().run(
        {
            "endpoint": "https://api.example.com",
            "allow_network": True,
            "timeout": 5,
        }
    )
    assert result.success is False
    assert seen["address"] == ("api.example.com", 443)
    assert seen["timeout"] == 5


def test_refuses_host_that_was_not_listed(monkeypatch) -> None:
    def boom(*_args: object, **_kwargs: object):
        raise AssertionError("should not connect")

    monkeypatch.setattr(api_tls_module.socket, "create_connection", boom)
    result = ApiTlsPostureAgent().run(
        {
            "endpoint": "https://api.example.com",
            "allow_network": True,
            "allowed_hosts": ["other.example"],
        }
    )
    assert result.success is False
    assert result.errors
    assert "not in the hosts" in result.errors[0]


def test_refuses_redirect_to_another_host() -> None:
    agent = ApiTlsPostureAgent()
    with pytest.raises(ValueError, match="redirect"):
        agent.refuse_cross_host_redirect(
            "https://api.example.com/",
            "https://evil.example/",
            {"api.example.com"},
        )
    agent.refuse_cross_host_redirect(
        "https://api.example.com/a",
        "https://api.example.com/b",
        {"api.example.com"},
    )


def test_tls_posture_does_not_use_an_http_client() -> None:
    source = Path(api_tls_module.__file__).read_text(encoding="utf-8")
    assert "urlopen" not in source
    assert "HTTPRedirectHandler" not in source
