from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from certguard.agents.x509_parser import X509ParserAgent


def _write_cert(
    path: Path,
    *,
    common_name: str = "example.com",
    san_dns: list[str] | None = None,
    days: int = 90,
    rsa_bits: int = 2048,
    hash_algo: hashes.HashAlgorithm = hashes.SHA256(),
    include_san: bool = True,
    include_ski: bool = False,
    include_basic_constraints: bool = False,
    is_ca: bool = False,
    use_ec: bool = False,
) -> None:
    if use_ec:
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)

    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
    )
    if include_san:
        dns_names = san_dns or [common_name]
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in dns_names]),
            critical=False,
        )
    if include_ski:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    if include_basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True,
        )

    cert = builder.sign(private_key=key, algorithm=hash_algo)
    path.write_bytes(cert.public_bytes(Encoding.PEM))


def test_parser_extracts_subject_and_issuer(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    _write_cert(cert_path, common_name="test.example.com")

    result = X509ParserAgent().run({"cert_path": str(cert_path)})

    assert result.success is True
    assert "test.example.com" in result.data["subject"]
    assert "test.example.com" in result.data["issuer"]
    assert result.data["common_name"] == "test.example.com"


def test_parser_extracts_validity_window(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    _write_cert(cert_path, days=365)

    result = X509ParserAgent().run({"cert_path": str(cert_path)})

    assert result.success is True
    assert result.data["validity_days"] == 365


def test_parser_extracts_san_values(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    _write_cert(cert_path, san_dns=["a.example.com", "b.example.com"])

    result = X509ParserAgent().run({"cert_path": str(cert_path)})

    assert result.data["san_dns"] == ["a.example.com", "b.example.com"]


def test_parser_returns_empty_san_when_extension_missing(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    _write_cert(cert_path, include_san=False)

    result = X509ParserAgent().run({"cert_path": str(cert_path)})

    assert result.success is True
    assert result.data["san_dns"] == []


def test_parser_detects_rsa_key_size(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    _write_cert(cert_path, rsa_bits=4096)

    result = X509ParserAgent().run({"cert_path": str(cert_path)})

    assert result.data["is_rsa"] is True
    assert result.data["rsa_key_size"] == 4096


def test_parser_detects_ec_key_as_non_rsa(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    _write_cert(cert_path, use_ec=True)

    result = X509ParserAgent().run({"cert_path": str(cert_path)})

    assert result.data["is_rsa"] is False
    assert result.data["rsa_key_size"] is None


def test_parser_extracts_signature_algorithm(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    _write_cert(cert_path, hash_algo=hashes.SHA384())

    result = X509ParserAgent().run({"cert_path": str(cert_path)})

    assert result.data["signature_algorithm"] == "sha384"


def test_parser_extracts_ski_when_present(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    _write_cert(cert_path, include_ski=True)

    result = X509ParserAgent().run({"cert_path": str(cert_path)})

    assert result.data["has_subject_key_identifier"] is True
    assert isinstance(result.data["subject_key_identifier"], str)
    assert len(result.data["subject_key_identifier"]) > 0


def test_parser_reports_missing_ski(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    _write_cert(cert_path, include_ski=False)

    result = X509ParserAgent().run({"cert_path": str(cert_path)})

    assert result.data["has_subject_key_identifier"] is False
    assert result.data["subject_key_identifier"] is None


def test_parser_extracts_basic_constraints(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    _write_cert(cert_path, include_basic_constraints=True, is_ca=False)

    result = X509ParserAgent().run({"cert_path": str(cert_path)})

    assert result.data["basic_constraints_ca"] is False


def test_parser_extracts_critical_extension_oids(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    _write_cert(cert_path, include_basic_constraints=True, is_ca=True)

    result = X509ParserAgent().run({"cert_path": str(cert_path)})

    assert "2.5.29.19" in result.data["critical_extension_oids"]


def test_parser_fails_for_missing_file() -> None:
    result = X509ParserAgent().run({"cert_path": "/nonexistent/cert.pem"})

    assert result.success is False
    assert len(result.errors) > 0


def test_parser_fails_for_invalid_pem(tmp_path: Path) -> None:
    cert_path = tmp_path / "bad.pem"
    cert_path.write_text("not a real certificate", encoding="utf-8")

    result = X509ParserAgent().run({"cert_path": str(cert_path)})

    assert result.success is False
    assert "PEM" in result.errors[0] or "parse" in result.errors[0].lower()
