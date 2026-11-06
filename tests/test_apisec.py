from __future__ import annotations

import contextlib
import ipaddress
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import certguard.agents.api_tls_posture as api_tls_module
from certguard.agents.api_tls_posture import (
    ApiTlsPostureAgent,
    classify_verification_failure,
    trust_failure_detail,
)
from certguard.cli import main


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
    assert result.data["risk_level"] == "UNKNOWN"
    assert result.data["evaluation_status"] == "error"


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

    def fake_dns(host: str, port: int, *args: object, **kwargs: object):
        seen["dns"] = (host, port)
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("203.0.113.10", port),
            )
        ]

    def fake_connect(self: socket.socket, address: tuple[str, int]) -> None:
        seen["address"] = address
        seen["timeout"] = self.gettimeout()
        raise OSError("stop")

    monkeypatch.setattr(api_tls_module.socket, "getaddrinfo", fake_dns)
    monkeypatch.setattr(api_tls_module.socket.socket, "connect", fake_connect)
    result = ApiTlsPostureAgent().run(
        {
            "endpoint": "https://api.example.com",
            "allow_network": True,
            "timeout": 5,
        }
    )
    assert result.success is False
    assert result.errors
    assert result.checks == []
    assert result.data["evaluation_status"] == "error"
    assert result.data["risk_level"] == "UNKNOWN"
    assert seen["dns"] == ("api.example.com", 443)
    assert seen["address"] == ("203.0.113.10", 443)
    assert seen["timeout"] == 5


def test_refuses_host_that_was_not_listed(monkeypatch) -> None:
    def boom(*_args: object, **_kwargs: object):
        raise AssertionError("should not connect")

    monkeypatch.setattr(api_tls_module.socket, "getaddrinfo", boom)
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


def test_inspection_context_does_not_trust_the_peer() -> None:
    agent = ApiTlsPostureAgent()
    inspected = agent._build_inspection_context()
    verified = agent._build_ssl_context()
    assert inspected.verify_mode == ssl.CERT_NONE
    assert inspected.check_hostname is False
    assert inspected.minimum_version == ssl.TLSVersion.TLSv1_2
    assert verified.verify_mode == ssl.CERT_REQUIRED
    assert verified.check_hostname is True
    assert verified.minimum_version == ssl.TLSVersion.TLSv1_2


@pytest.mark.parametrize(
    ("code", "message", "kind"),
    [
        (10, "certificate has expired", "expired"),
        (9, "certificate is not yet valid", "not_yet_valid"),
        (
            62,
            "Hostname mismatch, certificate is not valid for 'wrong.host.example'.",
            "hostname_mismatch",
        ),
        (64, "IP address mismatch, certificate is not valid for '127.0.0.1'.", "hostname_mismatch"),
        (18, "self-signed certificate", "self_signed"),
        (19, "self signed certificate in certificate chain", "self_signed"),
        (20, "unable to get local issuer certificate", "untrusted_issuer"),
        (2, "unable to get issuer certificate", "untrusted_issuer"),
    ],
)
def test_classify_openssl_verify_codes(code: int, message: str, kind: str) -> None:
    exc = ssl.SSLCertVerificationError(code, message)
    assert classify_verification_failure(exc) == kind
    detail = trust_failure_detail(kind, message)  # type: ignore[arg-type]
    assert "not trusted" in detail
    assert "_ssl.c" not in detail


def test_classify_message_without_verify_code() -> None:
    expired = ssl.SSLError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        "certificate has expired (_ssl.c:1000)"
    )
    mismatch = ssl.SSLError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        "Hostname mismatch, certificate is not valid for 'wrong.host.badssl.com'."
    )
    issuer = ssl.SSLError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        "unable to get local issuer certificate (_ssl.c:1000)"
    )
    other = ssl.SSLCertVerificationError(999, "application verification failure")
    assert classify_verification_failure(expired) == "expired"
    assert classify_verification_failure(mismatch) == "hostname_mismatch"
    assert classify_verification_failure(issuer) == "untrusted_issuer"
    assert classify_verification_failure(other) == "other"
    assert "application verification failure" in trust_failure_detail(
        "other", "application verification failure"
    )


def test_verification_failure_is_a_finding_and_reads_the_same_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pem = Path("tests/certificates/weak_key_cert.pem").read_text(encoding="utf-8")
    presented = api_tls_module.x509.load_pem_x509_certificate(pem.encode("utf-8"))
    key = presented.public_key()
    assert isinstance(key, rsa.RSAPublicKey)
    assert key.key_size == 1024

    resolutions: list[str] = []
    connects: list[tuple[str, int]] = []
    verified_handshakes: list[bool] = []

    def fake_dns(host: str, port: int, *args: object, **kwargs: object):
        resolutions.append(host)
        ip = "203.0.113.10" if len(resolutions) == 1 else "198.51.100.8"
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    class _Sock:
        def __init__(self, sockaddr: tuple[str, int]) -> None:
            self.sockaddr = sockaddr

        def getpeername(self) -> tuple[str, int]:
            return self.sockaddr

        def close(self) -> None:
            return None

        def settimeout(self, value: float) -> None:
            return None

    def fake_connect(
        self: ApiTlsPostureAgent,
        family: int,
        socktype: int,
        proto: int,
        sockaddr: tuple[str, int],
        timeout: float,
    ) -> _Sock:
        del family, socktype, proto, timeout
        connects.append(sockaddr)
        return _Sock(sockaddr)

    def fake_handshake(
        self: ApiTlsPostureAgent, tcp: object, host: str, *, verify: bool
    ) -> dict[str, str]:
        del tcp, host
        verified_handshakes.append(verify)
        if verify:
            raise ssl.SSLCertVerificationError(20, "unable to get local issuer certificate")
        return {
            "certificate_pem": pem,
            "tls_version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        }

    monkeypatch.setattr(api_tls_module.socket, "getaddrinfo", fake_dns)
    monkeypatch.setattr(ApiTlsPostureAgent, "_connect", fake_connect)
    monkeypatch.setattr(ApiTlsPostureAgent, "_handshake", fake_handshake)

    result = ApiTlsPostureAgent().run(
        {"endpoint": "https://rsa1024.example", "allow_network": True, "timeout": 5}
    )
    assert resolutions == ["rsa1024.example"]
    assert connects == [("203.0.113.10", 443), ("203.0.113.10", 443)]
    assert verified_handshakes == [True, False]
    assert result.errors == []
    assert result.success is False
    assert result.data["risk_level"] == "HIGH"
    assert result.data["evaluation_status"] == "evaluated"
    assert result.data["certificate_source"] == "verification_disabled"
    assert "not trusted" in result.data["certificate_inspection"]
    assert "verification disabled" in result.data["certificate_inspection"]
    assert result.data["rsa_key_size"] == 1024
    trust = next(check for check in result.checks if check.name == "endpoint_certificate_trust")
    assert trust.status == "fail"
    assert trust.actual_value == "untrusted_issuer"
    assert "issuer" in trust.details.lower() or "chain" in trust.details.lower()
    rsa_check = next(check for check in result.checks if check.name == "endpoint_rsa_key_size")
    assert rsa_check.status == "fail"
    assert "1024" in rsa_check.details


def test_expired_finding_without_a_certificate_still_names_the_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_fetch(self: ApiTlsPostureAgent, host: str, port: int, *, timeout: float):
        del self, host, port, timeout
        return {
            "verification_ok": False,
            "verification_failure": "expired",
            "verification_message": "certificate has expired",
            "certificate_source": "unavailable",
        }

    monkeypatch.setattr(ApiTlsPostureAgent, "_fetch_tls_posture", fake_fetch)
    result = ApiTlsPostureAgent().run(
        {"endpoint": "https://expired.example", "allow_network": True}
    )
    assert result.errors == []
    assert result.data["risk_level"] == "HIGH"
    names = {check.name: check for check in result.checks}
    assert names["endpoint_certificate_trust"].status == "fail"
    assert "expired" in names["endpoint_certificate_trust"].details.lower()
    assert names["endpoint_certificate_expiry"].status == "fail"
    assert "endpoint_hostname_match" not in names
    assert "endpoint_rsa_key_size" not in names


def test_hostname_mismatch_fails_the_name_control(monkeypatch: pytest.MonkeyPatch) -> None:
    pem = Path("tests/certificates/valid_cert.pem").read_text(encoding="utf-8")

    def fake_fetch(self: ApiTlsPostureAgent, host: str, port: int, *, timeout: float):
        del self, host, port, timeout
        return {
            "verification_ok": False,
            "verification_failure": "hostname_mismatch",
            "certificate_pem": pem,
            "tls_version": "TLSv1.2",
            "cipher_suite": "TLS_AES_128_GCM_SHA384",
            "certificate_source": "verification_disabled",
        }

    monkeypatch.setattr(ApiTlsPostureAgent, "_fetch_tls_posture", fake_fetch)
    result = ApiTlsPostureAgent().run(
        {"endpoint": "https://wrong.host.example", "allow_network": True}
    )
    hostname = next(check for check in result.checks if check.name == "endpoint_hostname_match")
    trust = next(check for check in result.checks if check.name == "endpoint_certificate_trust")
    assert trust.status == "fail"
    assert trust.actual_value == "hostname_mismatch"
    assert hostname.status == "fail"
    assert "wrong.host.example" in hostname.details
    assert result.data["risk_level"] == "HIGH"
    assert result.errors == []


@pytest.mark.parametrize(
    ("error", "snippet"),
    [
        (
            socket.gaierror(socket.EAI_NONAME, "Name or service not known"),
            "Name or service not known",
        ),
        (TimeoutError("timed out"), "timed out"),
        (ConnectionRefusedError(111, "Connection refused"), "Connection refused"),
    ],
)
def test_operational_failures_stay_errors(
    monkeypatch: pytest.MonkeyPatch, error: OSError, snippet: str
) -> None:
    inspections = {"count": 0}

    def fake_dns(host: str, port: int, *args: object, **kwargs: object):
        del host, port, args, kwargs
        if isinstance(error, socket.gaierror):
            raise error
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.10", 443))]

    def fake_connect(self: ApiTlsPostureAgent, *args: object, **kwargs: object) -> object:
        del self, args, kwargs
        raise error

    def fake_inspect(self: ApiTlsPostureAgent, *args: object, **kwargs: object) -> None:
        del self, args, kwargs
        inspections["count"] += 1
        raise AssertionError("inspection handshake is only for verification failures")

    monkeypatch.setattr(api_tls_module.socket, "getaddrinfo", fake_dns)
    monkeypatch.setattr(ApiTlsPostureAgent, "_connect", fake_connect)
    monkeypatch.setattr(ApiTlsPostureAgent, "_read_presented_certificate", fake_inspect)
    result = ApiTlsPostureAgent().run(
        {"endpoint": "https://api.example.com", "allow_network": True}
    )
    assert result.success is False
    assert result.checks == []
    assert result.errors
    assert snippet in result.errors[0]
    assert result.data["risk_level"] == "UNKNOWN"
    assert result.data["evaluation_status"] == "error"
    assert result.data["tls_version"] is None
    assert inspections["count"] == 0


def test_protocol_error_does_not_disable_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []

    def fake_dns(host: str, port: int, *args: object, **kwargs: object):
        del host, args, kwargs
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.10", port))
        ]

    class _Sock:
        def getpeername(self) -> tuple[str, int]:
            return ("203.0.113.10", 443)

        def close(self) -> None:
            return None

    def fake_connect(self: ApiTlsPostureAgent, *args: object, **kwargs: object) -> _Sock:
        del self, args, kwargs
        return _Sock()

    def fake_handshake(
        self: ApiTlsPostureAgent, tcp: object, host: str, *, verify: bool
    ) -> dict[str, str]:
        del self, tcp, host
        calls.append(verify)
        raise ssl.SSLError("WRONG_VERSION_NUMBER")

    monkeypatch.setattr(api_tls_module.socket, "getaddrinfo", fake_dns)
    monkeypatch.setattr(ApiTlsPostureAgent, "_connect", fake_connect)
    monkeypatch.setattr(ApiTlsPostureAgent, "_handshake", fake_handshake)
    result = ApiTlsPostureAgent().run(
        {"endpoint": "https://api.example.com", "allow_network": True}
    )
    assert calls == [True]
    assert result.errors
    assert result.data["evaluation_status"] == "error"
    assert result.data["risk_level"] == "UNKNOWN"
    assert "WRONG_VERSION_NUMBER" in result.errors[0]


def test_inspection_is_discarded_when_the_peer_ip_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connects = {"n": 0}

    def fake_dns(host: str, port: int, *args: object, **kwargs: object):
        del host, args, kwargs
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.10", port))
        ]

    class _Sock:
        def __init__(self, ip: str) -> None:
            self.ip = ip

        def getpeername(self) -> tuple[str, int]:
            return (self.ip, 443)

        def close(self) -> None:
            return None

    def fake_connect(self: ApiTlsPostureAgent, *args: object, **kwargs: object) -> _Sock:
        del self, args, kwargs
        connects["n"] += 1
        ip = "203.0.113.10" if connects["n"] == 1 else "198.51.100.9"
        return _Sock(ip)

    def fake_handshake(
        self: ApiTlsPostureAgent, tcp: object, host: str, *, verify: bool
    ) -> dict[str, str]:
        del self, tcp, host
        if verify:
            raise ssl.SSLCertVerificationError(10, "certificate has expired")
        raise AssertionError("refusing to read a certificate from a different IP")

    monkeypatch.setattr(api_tls_module.socket, "getaddrinfo", fake_dns)
    monkeypatch.setattr(ApiTlsPostureAgent, "_connect", fake_connect)
    monkeypatch.setattr(ApiTlsPostureAgent, "_handshake", fake_handshake)
    result = ApiTlsPostureAgent().run(
        {"endpoint": "https://expired.example", "allow_network": True}
    )
    assert connects["n"] == 2
    assert result.errors == []
    assert result.data["certificate_source"] == "unavailable"
    assert result.data["rsa_key_size"] is None
    assert result.data["risk_level"] == "HIGH"
    trust = next(check for check in result.checks if check.name == "endpoint_certificate_trust")
    assert trust.actual_value == "expired"


def test_cli_prints_findings_for_a_verification_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pem = Path("tests/certificates/sha1_cert.pem").read_text(encoding="utf-8")

    def fake_fetch(self: ApiTlsPostureAgent, host: str, port: int, *, timeout: float):
        del self, host, port, timeout
        return {
            "verification_ok": False,
            "verification_failure": "expired",
            "certificate_pem": pem,
            "tls_version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "certificate_source": "verification_disabled",
        }

    monkeypatch.setattr(ApiTlsPostureAgent, "_fetch_tls_posture", fake_fetch)
    code = main(["--mode", "apisec", "--allow-network", "--endpoint", "https://expired.example"])
    captured = capsys.readouterr()
    assert code == 3
    assert "ERROR:" not in captured.err
    assert "Policy result: FAIL" in captured.out
    assert "Risk Level: HIGH" in captured.out
    assert "TLS Version: TLSv1.2" in captured.out
    assert "TLS Version: None" not in captured.out
    assert "Risk Level: None" not in captured.out
    assert "Success:" not in captured.out
    assert "Certificate inspection:" in captured.out
    assert "not trusted" in captured.out
    assert "endpoint_certificate_trust: FAIL" in captured.out
    assert "endpoint_certificate_expiry: FAIL" in captured.out


def test_cli_prints_a_defined_status_for_operational_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_dns(*args: object, **kwargs: object):
        del args, kwargs
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(api_tls_module.socket, "getaddrinfo", fake_dns)
    code = main(["--mode", "apisec", "--allow-network", "--endpoint", "https://missing.example"])
    captured = capsys.readouterr()
    assert code == 2
    assert "ERROR:" in captured.err
    assert "Name or service not known" in captured.err
    assert "Status: ERROR" in captured.out
    assert "Risk Level: UNKNOWN" in captured.out
    assert "TLS Version: unavailable" in captured.out
    assert "Cipher Suite: unavailable" in captured.out
    assert "Risk Level: None" not in captured.out
    assert "Policy result:" not in captured.out


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _key()
    now = datetime.now(UTC)
    subject = _name("Neakam test CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(
    *,
    issuer_key: rsa.RSAPrivateKey,
    issuer: x509.Name,
    not_before: datetime,
    not_after: datetime,
    serial: int,
    san_ip: bool = True,
    dns_name: str | None = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _key()
    subject = _name(dns_name or "127.0.0.1")
    names: list[x509.GeneralName]
    if dns_name:
        names = [x509.DNSName(dns_name)]
    elif san_ip:
        names = [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    else:
        names = []
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False,
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
        critical=False,
    )
    return key, builder.sign(issuer_key, hashes.SHA256())


def _serve(
    tmp_path: Path, cert: x509.Certificate, key: rsa.RSAPrivateKey
) -> tuple[int, threading.Event, list[int]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    cert_path = tmp_path / "server.pem"
    key_path = tmp_path / "server.key"
    _write_cert(cert_path, cert)
    _write_key(key_path, key)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    sock.settimeout(0.2)
    port = sock.getsockname()[1]
    stop = threading.Event()
    hits: list[int] = []

    def loop() -> None:
        while not stop.is_set():
            try:
                conn, _addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            hits.append(1)
            try:
                tls = context.wrap_socket(conn, server_side=True)
                with contextlib.suppress(OSError):
                    tls.recv(1)
                tls.close()
            except (ssl.SSLError, OSError):
                with contextlib.suppress(OSError):
                    conn.close()
        with contextlib.suppress(OSError):
            sock.close()

    threading.Thread(target=loop, daemon=True).start()
    return port, stop, hits


def _trusting(ca_pem: bytes) -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=ca_pem.decode("utf-8"))
    return context


def test_local_expired_certificate_is_a_high_finding(tmp_path: Path) -> None:
    ca_key, ca_cert = _ca()
    now = datetime.now(UTC)
    leaf_key, leaf = _leaf(
        issuer_key=ca_key,
        issuer=ca_cert.subject,
        not_before=now - timedelta(days=40),
        not_after=now - timedelta(days=5),
        serial=2,
    )
    port, stop, hits = _serve(tmp_path, leaf, leaf_key)
    agent = ApiTlsPostureAgent()
    agent._build_ssl_context = lambda: _trusting(  # type: ignore[method-assign]
        ca_cert.public_bytes(serialization.Encoding.PEM)
    )
    try:
        result = agent.run(
            {
                "endpoint": f"https://127.0.0.1:{port}",
                "allow_network": True,
                "timeout": 3,
            }
        )
    finally:
        stop.set()
    assert result.errors == []
    assert result.success is False
    assert result.data["risk_level"] == "HIGH"
    assert result.data["certificate_source"] == "verification_disabled"
    assert result.data["rsa_key_size"] == 2048
    assert hits == [1, 1]
    trust = next(check for check in result.checks if check.name == "endpoint_certificate_trust")
    expiry = next(check for check in result.checks if check.name == "endpoint_certificate_expiry")
    hostname = next(check for check in result.checks if check.name == "endpoint_hostname_match")
    assert trust.status == "fail"
    assert trust.actual_value == "expired"
    assert "expired" in trust.details.lower()
    assert expiry.status == "fail"
    assert hostname.status == "pass"


def test_local_self_signed_and_unknown_issuer_are_findings(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    self_key = _key()
    subject = _name("127.0.0.1")
    self_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(self_key.public_key())
        .serial_number(3)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(self_key, hashes.SHA256())
    )
    port, stop, hits = _serve(tmp_path / "self", self_cert, self_key)
    try:
        self_signed = ApiTlsPostureAgent().run(
            {
                "endpoint": f"https://127.0.0.1:{port}",
                "allow_network": True,
                "timeout": 3,
            }
        )
    finally:
        stop.set()
    assert self_signed.errors == []
    trust = next(
        check for check in self_signed.checks if check.name == "endpoint_certificate_trust"
    )
    assert trust.actual_value == "self_signed"
    assert self_signed.data["risk_level"] == "HIGH"
    assert hits == [1, 1]

    ca_key, ca_cert = _ca()
    leaf_key, leaf = _leaf(
        issuer_key=ca_key,
        issuer=ca_cert.subject,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=30),
        serial=4,
    )
    port, stop, hits = _serve(tmp_path / "issuer", leaf, leaf_key)
    try:
        untrusted = ApiTlsPostureAgent().run(
            {
                "endpoint": f"https://127.0.0.1:{port}",
                "allow_network": True,
                "timeout": 3,
            }
        )
    finally:
        stop.set()
    assert untrusted.errors == []
    trust = next(check for check in untrusted.checks if check.name == "endpoint_certificate_trust")
    assert trust.actual_value == "untrusted_issuer"
    assert "issuer" in trust.details.lower() or "chain" in trust.details.lower()
    assert untrusted.data["certificate_source"] == "verification_disabled"
    assert hits == [1, 1]


def test_local_name_mismatch_and_not_yet_valid(tmp_path: Path) -> None:
    ca_key, ca_cert = _ca()
    now = datetime.now(UTC)
    mismatch_key, mismatch = _leaf(
        issuer_key=ca_key,
        issuer=ca_cert.subject,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=40),
        serial=5,
        dns_name="other.example",
    )
    future_key, future = _leaf(
        issuer_key=ca_key,
        issuer=ca_cert.subject,
        not_before=now + timedelta(days=10),
        not_after=now + timedelta(days=40),
        serial=6,
    )
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    port, stop, _hits = _serve(tmp_path / "name", mismatch, mismatch_key)
    agent = ApiTlsPostureAgent()
    agent._build_ssl_context = lambda: _trusting(ca_pem)  # type: ignore[method-assign]
    try:
        named = agent.run(
            {
                "endpoint": f"https://127.0.0.1:{port}",
                "allow_network": True,
                "timeout": 3,
            }
        )
    finally:
        stop.set()
    assert named.errors == []
    trust = next(check for check in named.checks if check.name == "endpoint_certificate_trust")
    hostname = next(check for check in named.checks if check.name == "endpoint_hostname_match")
    assert trust.actual_value == "hostname_mismatch"
    assert hostname.status == "fail"

    port, stop, _hits = _serve(tmp_path / "future", future, future_key)
    agent = ApiTlsPostureAgent()
    agent._build_ssl_context = lambda: _trusting(ca_pem)  # type: ignore[method-assign]
    try:
        early = agent.run(
            {
                "endpoint": f"https://127.0.0.1:{port}",
                "allow_network": True,
                "timeout": 3,
            }
        )
    finally:
        stop.set()
    assert early.errors == []
    trust = next(check for check in early.checks if check.name == "endpoint_certificate_trust")
    assert trust.actual_value == "not_yet_valid"
    assert "not yet valid" in trust.details.lower()
    assert early.data["risk_level"] == "HIGH"


def test_local_verified_certificate_opens_one_connection(tmp_path: Path) -> None:
    ca_key, ca_cert = _ca()
    now = datetime.now(UTC)
    leaf_key, leaf = _leaf(
        issuer_key=ca_key,
        issuer=ca_cert.subject,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=60),
        serial=7,
    )
    port, stop, hits = _serve(tmp_path, leaf, leaf_key)
    agent = ApiTlsPostureAgent()
    agent._build_ssl_context = lambda: _trusting(  # type: ignore[method-assign]
        ca_cert.public_bytes(serialization.Encoding.PEM)
    )
    try:
        result = agent.run(
            {
                "endpoint": f"https://127.0.0.1:{port}",
                "allow_network": True,
                "timeout": 3,
            }
        )
    finally:
        stop.set()
    assert result.errors == []
    assert result.success is True
    assert result.data["risk_level"] == "LOW"
    assert result.data["certificate_source"] == "verified"
    assert result.data["certificate_inspection"] is None
    assert hits == [1]
    trust = next(check for check in result.checks if check.name == "endpoint_certificate_trust")
    assert trust.status == "pass"
