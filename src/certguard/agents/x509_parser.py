from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult


class X509ParserAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="x509_parser_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        cert_path = Path(context["cert_path"])
        if not cert_path.exists():
            return AgentResult(
                agent=self.name,
                success=False,
                errors=[f"Certificate file not found: {cert_path}"],
            )

        raw = cert_path.read_bytes()
        requested_kind = context.get("input_kind")
        if requested_kind in {"csr", "certificate"}:
            kind = requested_kind
        else:
            kind = self._detect_pem_kind(raw)
        evaluated_at = self._evaluated_at(context)

        if kind == "csr":
            return self._parse_csr(raw, evaluated_at)

        try:
            cert = x509.load_pem_x509_certificate(raw)
        except ValueError:
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Failed to parse certificate. Ensure PEM format is valid."],
            )

        try:
            san_extension = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            san_values = san_extension.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_values = []

        key_info = self._public_key_info(cert.public_key())
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        validity = not_after - not_before

        parser_data: dict[str, Any] = {
            "input_kind": "certificate",
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "common_name": self._safe_cn(cert.subject),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "evaluated_at": evaluated_at.isoformat(),
            # CA/Browser Forum BR 1.6.1 defines the Validity Period as the
            # period from notBefore through notAfter. The whole-day field is
            # retained for compatibility; validity_seconds is used for exact
            # enforcement so a partial extra day cannot be rounded away.
            "validity_days": validity.days,
            "validity_seconds": int(validity.total_seconds()),
            "is_expired": not_after < evaluated_at,
            "is_not_yet_valid": not_before > evaluated_at,
            "days_until_expiry": (not_after - evaluated_at).days,
            "san_dns": san_values,
            # Digest only, retained for backwards compatibility.
            "signature_algorithm": self._signature_hash_name(cert),
            "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
            "signature_algorithm_name": self._signature_algorithm_name(cert),
            "key_algorithm": key_info["algorithm"],
            "key_size_bits": key_info["size_bits"],
            "ec_curve": key_info["curve"],
            # Retained so existing policies and consumers keep working.
            "is_rsa": key_info["algorithm"] == "rsa",
            "rsa_key_size": key_info["size_bits"] if key_info["algorithm"] == "rsa" else None,
            "serial_number": format(cert.serial_number, "x"),
            "serial_number_bits": cert.serial_number.bit_length(),
            "basic_constraints_ca": self._basic_constraints_ca(cert),
            "key_usage": self._key_usage_flags(cert),
            "extended_key_usage": self._extended_key_usage(cert),
            "has_subject_key_identifier": self._has_extension(
                cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER
            ),
            "has_authority_key_identifier": self._has_extension(
                cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            ),
            "subject_key_identifier": self._subject_key_identifier(cert),
            "authority_key_identifier": self._authority_key_identifier(cert),
            "critical_extension_oids": self._critical_extension_oids(cert),
            "sct_count": self._sct_count(cert),
        }

        return AgentResult(agent=self.name, success=True, data=parser_data)

    def _evaluated_at(self, context: dict[str, Any]) -> datetime:
        evaluated_at = context.get("evaluated_at") or datetime.now(UTC)
        if isinstance(evaluated_at, str):
            evaluated_at = datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
        if evaluated_at.tzinfo is None:
            return evaluated_at.replace(tzinfo=UTC)
        return evaluated_at

    def _detect_pem_kind(self, raw: bytes) -> str:
        if (
            b"BEGIN CERTIFICATE REQUEST" in raw
            or b"BEGIN NEW CERTIFICATE REQUEST" in raw
        ):
            return "csr"
        return "certificate"

    def _parse_csr(self, raw: bytes, evaluated_at: datetime) -> AgentResult:
        try:
            csr = x509.load_pem_x509_csr(raw)
        except ValueError:
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["Failed to parse CSR. Ensure PEM format is valid."],
            )

        try:
            san_extension = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            san_values = san_extension.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_values = []

        key_info = self._public_key_info(csr.public_key())
        parser_data: dict[str, Any] = {
            "input_kind": "csr",
            "subject": csr.subject.rfc4514_string(),
            "issuer": None,
            "common_name": self._safe_cn(csr.subject),
            "not_before": None,
            "not_after": None,
            "evaluated_at": evaluated_at.isoformat(),
            "validity_days": None,
            "validity_seconds": None,
            "is_expired": None,
            "is_not_yet_valid": None,
            "days_until_expiry": None,
            "san_dns": san_values,
            "signature_algorithm": self._signature_hash_name(csr),
            "signature_algorithm_oid": csr.signature_algorithm_oid.dotted_string,
            "signature_algorithm_name": self._signature_algorithm_name(csr),
            "key_algorithm": key_info["algorithm"],
            "key_size_bits": key_info["size_bits"],
            "ec_curve": key_info["curve"],
            "is_rsa": key_info["algorithm"] == "rsa",
            "rsa_key_size": key_info["size_bits"] if key_info["algorithm"] == "rsa" else None,
            "serial_number": None,
            "serial_number_bits": None,
            "basic_constraints_ca": None,
            "key_usage": [],
            "extended_key_usage": [],
            "has_subject_key_identifier": False,
            "has_authority_key_identifier": False,
            "subject_key_identifier": None,
            "authority_key_identifier": None,
            "critical_extension_oids": [],
            "sct_count": 0,
        }
        return AgentResult(agent=self.name, success=True, data=parser_data)

    def _public_key_info(self, key: object) -> dict[str, Any]:
        """Normalise the public key into algorithm, size and curve.

        Previously only RSA was inspected, so every non-RSA key bypassed key
        strength policy entirely -- a 192-bit EC certificate evaluated as
        compliant. Normalising here lets policy reason about any key type.
        """

        if isinstance(key, rsa.RSAPublicKey):
            return {"algorithm": "rsa", "size_bits": key.key_size, "curve": None}
        if isinstance(key, ec.EllipticCurvePublicKey):
            return {
                "algorithm": "ec",
                "size_bits": key.curve.key_size,
                "curve": key.curve.name.lower(),
            }
        if isinstance(key, ed25519.Ed25519PublicKey):
            return {"algorithm": "ed25519", "size_bits": 256, "curve": "ed25519"}
        if isinstance(key, ed448.Ed448PublicKey):
            return {"algorithm": "ed448", "size_bits": 448, "curve": "ed448"}
        if isinstance(key, dsa.DSAPublicKey):
            return {"algorithm": "dsa", "size_bits": key.key_size, "curve": None}
        return {
            "algorithm": type(key).__name__.replace("PublicKey", "").lower() or "unknown",
            "size_bits": getattr(key, "key_size", None),
            "curve": None,
        }

    def _signature_hash_name(self, signed: x509.Certificate | x509.CertificateSigningRequest) -> str:
        if signed.signature_hash_algorithm is None:
            return "unknown"
        return signed.signature_hash_algorithm.name.lower()

    def _signature_algorithm_name(
        self, signed: x509.Certificate | x509.CertificateSigningRequest
    ) -> str:
        """Full signature algorithm identifier, not just the digest.

        BR 7.1.3.2 constrains the signature AlgorithmIdentifier (for example
        RSASSA-PSS versus RSASSA-PKCS1-v1_5), which the digest name alone
        cannot express.
        """
        name = getattr(signed.signature_algorithm_oid, "_name", None)
        if isinstance(name, str) and name:
            return name.lower()
        return signed.signature_algorithm_oid.dotted_string

    def _safe_cn(self, subject: x509.Name) -> str | None:
        attrs = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attrs:
            return None
        value = attrs[0].value
        return value if isinstance(value, str) else value.decode("utf-8", "replace")

    def _basic_constraints_ca(self, cert: x509.Certificate) -> bool | None:
        try:
            ext = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            return ext.ca
        except x509.ExtensionNotFound:
            return None

    def _key_usage_flags(self, cert: x509.Certificate) -> list[str]:
        try:
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            return []

        flags: list[tuple[str, bool]] = [
            ("digital_signature", usage.digital_signature),
            ("content_commitment", usage.content_commitment),
            ("key_encipherment", usage.key_encipherment),
            ("data_encipherment", usage.data_encipherment),
            ("key_agreement", usage.key_agreement),
            ("key_cert_sign", usage.key_cert_sign),
            ("crl_sign", usage.crl_sign),
        ]
        if usage.key_agreement:
            flags.extend(
                [
                    ("encipher_only", usage.encipher_only),
                    ("decipher_only", usage.decipher_only),
                ]
            )
        return [name for name, is_enabled in flags if is_enabled]

    def _sct_count(self, cert: x509.Certificate) -> int:
        try:
            extension = cert.extensions.get_extension_for_oid(
                ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
            )
        except x509.ExtensionNotFound:
            return 0
        value = extension.value
        try:
            return len(list(value))
        except TypeError:
            return 0

    def _extended_key_usage(self, cert: x509.Certificate) -> list[str]:
        try:
            ekus = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            return []
        return sorted(oid.dotted_string for oid in ekus)

    def _has_extension(self, cert: x509.Certificate, oid: ExtensionOID) -> bool:
        try:
            cert.extensions.get_extension_for_oid(oid)
            return True
        except x509.ExtensionNotFound:
            return False

    def _critical_extension_oids(self, cert: x509.Certificate) -> list[str]:
        return sorted(
            extension.oid.dotted_string
            for extension in cert.extensions
            if extension.critical
        )

    def _subject_key_identifier(self, cert: x509.Certificate) -> str | None:
        try:
            value = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_KEY_IDENTIFIER
            ).value
            return value.digest.hex()
        except x509.ExtensionNotFound:
            return None

    def _authority_key_identifier(self, cert: x509.Certificate) -> str | None:
        try:
            value = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            ).value
            return value.key_identifier.hex() if value.key_identifier is not None else None
        except x509.ExtensionNotFound:
            return None
