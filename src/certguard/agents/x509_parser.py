from __future__ import annotations

from datetime import datetime, timezone
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

        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
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

        # Evaluation time is captured explicitly because expiry checks make the
        # verdict time-dependent. An evidence artefact has to state the instant
        # the decision was made, not leave it implied.
        evaluated_at = context.get("evaluated_at") or datetime.now(timezone.utc)
        if isinstance(evaluated_at, str):
            evaluated_at = datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
        if evaluated_at.tzinfo is None:
            evaluated_at = evaluated_at.replace(tzinfo=timezone.utc)

        key_info = self._public_key_info(cert)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        parser_data: dict[str, Any] = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "common_name": self._safe_cn(cert),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "evaluated_at": evaluated_at.isoformat(),
            # CA/Browser Forum BR 1.6.1 defines the Validity Period as the
            # period from notBefore through notAfter. CertGuard measures it as
            # the whole-day difference (notAfter - notBefore), so a certificate
            # issued for exactly N days reports N. The boundary is asserted in
            # tests/test_validity_boundary.py at max-1, max and max+1 so this
            # interpretation cannot drift silently.
            "validity_days": (not_after - not_before).days,
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
        }

        return AgentResult(agent=self.name, success=True, data=parser_data)

    def _public_key_info(self, cert: x509.Certificate) -> dict[str, Any]:
        """Normalise the public key into algorithm, size and curve.

        Previously only RSA was inspected, so every non-RSA key bypassed key
        strength policy entirely -- a 192-bit EC certificate evaluated as
        compliant. Normalising here lets policy reason about any key type.
        """
        key = cert.public_key()

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

    def _signature_hash_name(self, cert: x509.Certificate) -> str:
        if cert.signature_hash_algorithm is None:
            return "unknown"
        return cert.signature_hash_algorithm.name.lower()

    def _signature_algorithm_name(self, cert: x509.Certificate) -> str:
        """Full signature algorithm identifier, not just the digest.

        BR 7.1.3.2 constrains the signature AlgorithmIdentifier (for example
        RSASSA-PSS versus RSASSA-PKCS1-v1_5), which the digest name alone
        cannot express.
        """
        name = getattr(cert.signature_algorithm_oid, "_name", None)
        if isinstance(name, str) and name:
            return name.lower()
        return cert.signature_algorithm_oid.dotted_string

    def _safe_cn(self, cert: x509.Certificate) -> str | None:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
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
