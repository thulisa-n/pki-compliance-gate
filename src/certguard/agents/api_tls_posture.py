from __future__ import annotations

import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult


class ApiTlsPostureAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="api_tls_posture_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        endpoint = context.get("endpoint")
        if not endpoint:
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["APISEC mode requires an endpoint URL."],
            )

        host, port = self._parse_endpoint(endpoint)
        pem = self._fetch_certificate_pem(host, port)
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))

        expires_in_days = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
        signature = (
            cert.signature_hash_algorithm.name.lower()
            if cert.signature_hash_algorithm is not None
            else "unknown"
        )
        key = cert.public_key()
        rsa_bits = key.key_size if isinstance(key, rsa.RSAPublicKey) else None

        checks = [
            CheckResult(
                name="endpoint_certificate_expiry",
                status="pass" if expires_in_days >= 30 else "fail",
                details=f"Certificate expires in {expires_in_days} days.",
                category="APISEC",
                severity="high",
                standard_reference="OWASP API Security Top 10: API8",
            ),
            CheckResult(
                name="endpoint_signature_algorithm",
                status="fail" if "sha1" in signature or "md5" in signature else "pass",
                details=f"Endpoint signature algorithm: {signature}.",
                category="APISEC",
                severity="critical",
                standard_reference="OWASP API Security Top 10: API8",
            ),
            CheckResult(
                name="endpoint_rsa_key_size",
                status=(
                    "pass"
                    if (rsa_bits is None or rsa_bits >= 2048)
                    else "fail"
                ),
                details=(
                    f"Endpoint RSA key size: {rsa_bits} bits."
                    if rsa_bits is not None
                    else "Endpoint key is non-RSA."
                ),
                category="APISEC",
                severity="high",
                standard_reference="OWASP API Security Top 10: API8",
            ),
        ]

        risk = self._risk(checks)
        return AgentResult(
            agent=self.name,
            success=all(item.status == "pass" for item in checks),
            checks=checks,
            data={
                "endpoint": endpoint,
                "host": host,
                "port": port,
                "expires_in_days": expires_in_days,
                "signature_algorithm": signature,
                "rsa_key_size": rsa_bits,
                "risk_level": risk,
            },
        )

    def _parse_endpoint(self, endpoint: str) -> tuple[str, int]:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"https", "tls"}:
            raise ValueError("Endpoint must use https:// or tls:// scheme.")
        host = parsed.hostname
        if not host:
            raise ValueError("Endpoint is missing hostname.")
        port = parsed.port or 443
        return host, port

    def _fetch_certificate_pem(self, host: str, port: int) -> str:
        # stdlib retrieval, sufficient for lightweight endpoint posture checks
        return ssl.get_server_certificate((host, port), timeout=10)

    def _risk(self, checks: list[CheckResult]) -> str:
        failed = [item for item in checks if item.status == "fail"]
        if not failed:
            return "LOW"
        if any((item.severity or "").lower() == "critical" for item in failed):
            return "HIGH"
        return "MEDIUM"
