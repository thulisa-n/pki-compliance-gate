from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult

DEFAULT_TLS_TIMEOUT_SECONDS = 10.0
MAX_TLS_TIMEOUT_SECONDS = 30.0


class ApiTlsPostureAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="api_tls_posture_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        endpoint = context.get("endpoint")
        if not endpoint or not isinstance(endpoint, str):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["APISEC mode requires an endpoint URL."],
            )
        if not context.get("allow_network"):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=[
                    "Refusing to contact the network. Pass --allow-network to opt in "
                    "to a live TLS check."
                ],
            )

        try:
            host, port = self._parse_endpoint(endpoint)
            allowed = self._allowed_hosts(context.get("allowed_hosts"), fallback=host)
            if host.lower() not in allowed:
                raise ValueError(
                    f"Refusing to contact {host}: it is not in the hosts you listed."
                )
            timeout = self._timeout_seconds(
                context.get("timeout", DEFAULT_TLS_TIMEOUT_SECONDS)
            )
            tls_posture = self._fetch_tls_posture(host, port, timeout=timeout)
            pem = tls_posture["certificate_pem"]
            tls_version = tls_posture["tls_version"]
            cipher_suite = tls_posture["cipher_suite"]
            cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
        except (KeyError, TypeError, ValueError, ssl.SSLError, OSError) as exc:
            return AgentResult(
                agent=self.name,
                success=False,
                errors=[self._public_error(exc)],
            )

        expires_in_days = (cert.not_valid_after_utc - datetime.now(UTC)).days
        signature = (
            cert.signature_hash_algorithm.name.lower()
            if cert.signature_hash_algorithm is not None
            else "unknown"
        )
        key = cert.public_key()
        rsa_bits = key.key_size if isinstance(key, rsa.RSAPublicKey) else None
        chain_posture = self._chain_posture(cert)

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
                name="endpoint_tls_version_policy",
                status="pass" if tls_version in {"TLSv1.2", "TLSv1.3"} else "fail",
                details=f"Negotiated TLS version: {tls_version}.",
                category="APISEC",
                severity="high",
                standard_reference="NIST SP 800-52r2",
            ),
            CheckResult(
                name="endpoint_cipher_policy",
                status="fail" if self._is_weak_cipher(cipher_suite) else "pass",
                details=f"Negotiated cipher suite: {cipher_suite}.",
                category="APISEC",
                severity="high",
                standard_reference="NIST SP 800-52r2",
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
            CheckResult(
                name="endpoint_chain_posture",
                status="pass" if chain_posture["ok"] else "fail",
                details=chain_posture["details"],
                category="APISEC",
                severity="high",
                standard_reference="RFC 5280",
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
                "tls_version": tls_version,
                "cipher_suite": cipher_suite,
                "signature_algorithm": signature,
                "rsa_key_size": rsa_bits,
                "chain_posture": chain_posture,
                "risk_level": risk,
            },
        )

    def _parse_endpoint(self, endpoint: str) -> tuple[str, int]:
        raw = endpoint.strip()
        if "://" not in raw:
            raw = "https://" + raw
        parsed = urlparse(raw)
        if parsed.scheme not in {"https", "tls"}:
            raise ValueError("Endpoint must use https:// or tls://.")
        host = parsed.hostname
        if not host:
            raise ValueError("Endpoint is missing a hostname.")
        if parsed.username or parsed.password:
            raise ValueError("Endpoint must not include credentials.")
        port = parsed.port or 443
        return host, port

    def _allowed_hosts(self, listed: object, *, fallback: str) -> set[str]:
        if listed is None:
            return {fallback.lower()}
        if isinstance(listed, str):
            items: list[object] = [listed]
        elif isinstance(listed, (list, tuple, set)):
            items = list(listed)
        else:
            raise ValueError("allowed hosts must be a list of hostnames.")
        hosts = {str(item).strip().lower() for item in items if str(item).strip()}
        if not hosts:
            raise ValueError("allowed hosts must name at least one host.")
        return hosts

    def _timeout_seconds(self, value: object) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise ValueError("TLS timeout must be a number of seconds.")
        try:
            timeout = float(value)
        except ValueError as exc:
            raise ValueError("TLS timeout must be a number of seconds.") from exc
        if timeout <= 0 or timeout > MAX_TLS_TIMEOUT_SECONDS:
            raise ValueError(
                "TLS timeout must be greater than 0 and at most "
                f"{MAX_TLS_TIMEOUT_SECONDS:g} seconds."
            )
        return timeout

    def _public_error(self, exc: BaseException) -> str:
        text = " ".join(str(exc).split())
        lowered = text.lower()
        if "-----begin" in lowered or "private key" in lowered or "licence" in lowered:
            return "Failed to evaluate endpoint TLS posture."
        if len(text) > 180:
            text = text[:177] + "..."
        return f"Failed to evaluate endpoint TLS posture: {text}"

    def refuse_cross_host_redirect(
        self,
        current_url: str,
        location: str,
        allowed_hosts: set[str],
    ) -> None:
        """Reject a redirect that would leave the host the user listed.

        The live check never speaks HTTP, so it cannot follow a redirect.
        This is the same rule a caller hits if a ``Location`` is ever offered:
        a different host is refused, and so is a redirect that is not on the
        allowlist. A same-host redirect is still not followed by the fetch
        below, which opens exactly one connection.
        """
        target = (urlparse(location).hostname or "").lower()
        current = (urlparse(current_url).hostname or "").lower()
        allowed = {item.lower() for item in allowed_hosts}
        if not target or target not in allowed or target != current:
            raise ValueError("Refusing to follow a redirect to another host.")

    def _fetch_tls_posture(
        self, host: str, port: int, *, timeout: float
    ) -> dict[str, str]:
        """Open one TLS connection to ``host`` and read the peer certificate.

        There is no HTTP client, so redirects are not followed. ``timeout``
        bounds both the TCP connect and the handshake.
        """
        context = self._build_ssl_context()
        with socket.create_connection((host, port), timeout=timeout) as tcp_sock:
            tcp_sock.settimeout(timeout)
            with context.wrap_socket(tcp_sock, server_hostname=host) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
                if not der_cert:
                    raise ValueError("Endpoint did not return a peer certificate.")
                pem = ssl.DER_cert_to_PEM_cert(der_cert)
                cipher = tls_sock.cipher()
                return {
                    "certificate_pem": pem,
                    "tls_version": tls_sock.version() or "unknown",
                    "cipher_suite": cipher[0] if cipher else "unknown",
                }

    def _build_ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        # Explicitly enforce modern TLS to satisfy secure transport policy.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def _is_weak_cipher(self, cipher_suite: str) -> bool:
        weak_markers = ("rc4", "3des", "des", "null", "anon", "export", "md5")
        normalized = cipher_suite.lower()
        return any(marker in normalized for marker in weak_markers)

    def _chain_posture(self, cert: x509.Certificate) -> dict[str, Any]:
        is_self_signed = cert.issuer == cert.subject
        has_ski = self._has_extension(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        has_aki = self._has_extension(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)

        if is_self_signed:
            return {
                "ok": True,
                "details": "Leaf certificate is self-signed; external chain validation not required for this posture check.",
                "self_signed": True,
                "has_ski": has_ski,
                "has_aki": has_aki,
            }
        if has_ski and has_aki:
            return {
                "ok": True,
                "details": "Leaf certificate contains SKI/AKI extensions suitable for chain linkage.",
                "self_signed": False,
                "has_ski": has_ski,
                "has_aki": has_aki,
            }
        return {
            "ok": False,
            "details": "Leaf certificate is not self-signed and is missing SKI or AKI extension required for strong chain posture.",
            "self_signed": False,
            "has_ski": has_ski,
            "has_aki": has_aki,
        }

    def _has_extension(self, cert: x509.Certificate, oid: ExtensionOID) -> bool:
        try:
            cert.extensions.get_extension_for_oid(oid)
            return True
        except x509.ExtensionNotFound:
            return False

    def _risk(self, checks: list[CheckResult]) -> str:
        failed = [item for item in checks if item.status == "fail"]
        if not failed:
            return "LOW"
        if any((item.severity or "").lower() == "critical" for item in failed):
            return "HIGH"
        return "MEDIUM"
