from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

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

        public_key = cert.public_key()
        rsa_bits = public_key.key_size if isinstance(public_key, rsa.RSAPublicKey) else None
        common_name = self._safe_cn(cert)
        basic_constraints_ca = self._basic_constraints_ca(cert)
        key_usage = self._key_usage_flags(cert)

        parser_data: dict[str, Any] = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "common_name": common_name,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "validity_days": (cert.not_valid_after_utc - cert.not_valid_before_utc).days,
            "san_dns": san_values,
            "signature_algorithm": self._signature_name(cert),
            "is_rsa": rsa_bits is not None,
            "rsa_key_size": rsa_bits,
            "basic_constraints_ca": basic_constraints_ca,
            "key_usage": key_usage,
        }

        return AgentResult(agent=self.name, success=True, data=parser_data)

    def _signature_name(self, cert: x509.Certificate) -> str:
        if cert.signature_hash_algorithm is None:
            return "unknown"
        return cert.signature_hash_algorithm.name.lower()

    def _safe_cn(self, cert: x509.Certificate) -> str | None:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attrs:
            return None
        return attrs[0].value

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
