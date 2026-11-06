from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult, Status

DEFAULT_TLS_TIMEOUT_SECONDS = 10.0
MAX_TLS_TIMEOUT_SECONDS = 30.0

#: Risk recorded when the endpoint could not be evaluated (DNS, timeout,
#: connection refused, and any other failure that is not a certificate finding).
OPERATIONAL_RISK_LEVEL = "UNKNOWN"

#: Printed when the presented certificate was read without trusting it.
INSPECTION_DETAIL = (
    "Presented certificate was read with verification disabled and is not trusted. "
    "It was used only to report expiry, key size, and signature algorithm."
)

VerificationKind = Literal[
    "expired",
    "not_yet_valid",
    "hostname_mismatch",
    "self_signed",
    "untrusted_issuer",
    "other",
]

# OpenSSL X509_V_ERR_* values observed from SSLCertVerificationError.verify_code.
_VERIFY_CODE_KIND: dict[int, VerificationKind] = {
    9: "not_yet_valid",  # X509_V_ERR_CERT_NOT_YET_VALID
    10: "expired",  # X509_V_ERR_CERT_HAS_EXPIRED
    18: "self_signed",  # X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
    19: "self_signed",  # X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
    2: "untrusted_issuer",  # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
    20: "untrusted_issuer",  # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
    21: "untrusted_issuer",  # X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
    27: "untrusted_issuer",  # X509_V_ERR_CERT_UNTRUSTED
    62: "hostname_mismatch",  # X509_V_ERR_HOSTNAME_MISMATCH
    64: "hostname_mismatch",  # X509_V_ERR_IP_ADDRESS_MISMATCH
}

_TRUST_DETAILS: dict[VerificationKind, str] = {
    "expired": "The endpoint certificate is not trusted because it has expired.",
    "not_yet_valid": "The endpoint certificate is not trusted because it is not yet valid.",
    "hostname_mismatch": (
        "The endpoint certificate is not trusted because the name on the "
        "certificate does not match the host."
    ),
    "self_signed": "The endpoint certificate is not trusted because it is self-signed.",
    "untrusted_issuer": (
        "The endpoint certificate is not trusted because the issuer is unknown "
        "or the certificate chain is incomplete."
    ),
    "other": "The endpoint certificate is not trusted because certificate verification failed.",
}


def is_certificate_verification_failure(exc: BaseException) -> bool:
    """True when the handshake reached certificate verification and it failed."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return True
    if getattr(exc, "reason", None) == "CERTIFICATE_VERIFY_FAILED":
        return True
    return "CERTIFICATE_VERIFY_FAILED" in str(exc)


def classify_verification_failure(exc: BaseException) -> VerificationKind:
    """Map a TLS verification error to a stable reason.

    Prefer ``verify_code`` when OpenSSL set it. Fall back to the message so a
    mocked error and a live handshake classify the same way.
    """
    code = getattr(exc, "verify_code", None)
    if not isinstance(code, int) and exc.args and isinstance(exc.args[0], int):
        code = exc.args[0]
    if isinstance(code, int) and code in _VERIFY_CODE_KIND:
        return _VERIFY_CODE_KIND[code]

    text = _verify_text(exc)
    if "not yet valid" in text:
        return "not_yet_valid"
    if "has expired" in text or "certificate expired" in text:
        return "expired"
    if "hostname mismatch" in text or "ip address mismatch" in text or "name mismatch" in text:
        return "hostname_mismatch"
    if "self-signed" in text or "self signed" in text:
        return "self_signed"
    if (
        "unable to get local issuer" in text
        or "unable to get issuer" in text
        or "unable to verify the first certificate" in text
        or "incomplete chain" in text
        or "unknown issuer" in text
        or "certificate untrusted" in text
    ):
        return "untrusted_issuer"
    return "other"


def trust_failure_detail(kind: VerificationKind, message: str | None = None) -> str:
    """Plain-English detail for a failed ``endpoint_certificate_trust`` check."""
    if kind != "other":
        return _TRUST_DETAILS[kind]
    extra = " ".join((message or "").split())
    lowered = extra.lower()
    if not extra or "-----begin" in lowered or "private key" in lowered:
        return _TRUST_DETAILS["other"]
    if len(extra) > 120:
        extra = extra[:117] + "..."
    return (
        "The endpoint certificate is not trusted because certificate "
        f"verification failed ({extra})."
    )


def _verify_text(exc: BaseException) -> str:
    message = getattr(exc, "verify_message", None)
    parts: list[str] = []
    if isinstance(message, str) and message.strip():
        parts.append(message)
    parts.extend(str(arg) for arg in exc.args if isinstance(arg, str))
    if not parts:
        parts.append(str(exc))
    return " ".join(parts).lower()


def _short_verify_message(exc: BaseException) -> str:
    message = getattr(exc, "verify_message", None)
    if isinstance(message, str) and message.strip():
        text = message
    else:
        text = " ".join(str(arg) for arg in exc.args if isinstance(arg, str))
        if not text:
            text = str(exc)
    text = " ".join(text.split())
    if "(_ssl.c" in text:
        text = text.split("(_ssl.c", 1)[0].rstrip()
    marker = "certificate verify failed:"
    lowered = text.lower()
    index = lowered.rfind(marker)
    if index != -1:
        text = text[index + len(marker) :].strip()
    if len(text) > 120:
        text = text[:117] + "..."
    return text


def _peer_ip(sock: socket.socket) -> str:
    peer = sock.getpeername()
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return str(peer)


def _same_ip(left: str, right: str) -> bool:
    try:
        return ipaddress.ip_address(left) == ipaddress.ip_address(right)
    except ValueError:
        return left == right


class ApiTlsPostureAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="api_tls_posture_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        endpoint = context.get("endpoint")
        if not endpoint or not isinstance(endpoint, str):
            return self._operational_error(
                str(endpoint) if endpoint else "",
                ValueError("APISEC mode requires an endpoint URL."),
                public_message="APISEC mode requires an endpoint URL.",
            )
        if not context.get("allow_network"):
            return self._operational_error(
                endpoint,
                ValueError(
                    "Refusing to contact the network. Pass --allow-network to opt in "
                    "to a live TLS check."
                ),
                public_message=(
                    "Refusing to contact the network. Pass --allow-network to opt in "
                    "to a live TLS check."
                ),
            )

        host: str | None = None
        port: int | None = None
        try:
            host, port = self._parse_endpoint(endpoint)
            allowed = self._allowed_hosts(context.get("allowed_hosts"), fallback=host)
            if host.lower() not in allowed:
                raise ValueError(f"Refusing to contact {host}: it is not in the hosts you listed.")
            timeout = self._timeout_seconds(context.get("timeout", DEFAULT_TLS_TIMEOUT_SECONDS))
            tls_posture = self._fetch_tls_posture(host, port, timeout=timeout)
            checks, assessed = self._assess(host, tls_posture)
        except (KeyError, TypeError, ValueError, ssl.SSLError, OSError) as exc:
            return self._operational_error(endpoint, exc, host=host, port=port)

        assessed.update(
            {
                "endpoint": endpoint,
                "host": host,
                "port": port,
            }
        )
        return AgentResult(
            agent=self.name,
            success=all(item.status == "pass" for item in checks),
            checks=checks,
            data=assessed,
        )

    def _operational_error(
        self,
        endpoint: str,
        exc: BaseException,
        *,
        host: str | None = None,
        port: int | None = None,
        public_message: str | None = None,
    ) -> AgentResult:
        return AgentResult(
            agent=self.name,
            success=False,
            errors=[public_message or self._public_error(exc)],
            data={
                "endpoint": endpoint or None,
                "host": host,
                "port": port,
                "risk_level": OPERATIONAL_RISK_LEVEL,
                "evaluation_status": "error",
                "tls_version": None,
                "cipher_suite": None,
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
        below, which opens a connection only to the resolved address.
        """
        target = (urlparse(location).hostname or "").lower()
        current = (urlparse(current_url).hostname or "").lower()
        allowed = {item.lower() for item in allowed_hosts}
        if not target or target not in allowed or target != current:
            raise ValueError("Refusing to follow a redirect to another host.")

    def _fetch_tls_posture(self, host: str, port: int, *, timeout: float) -> dict[str, Any]:
        """Open TLS to ``host`` and read the peer certificate.

        The name is resolved once. Every connection uses an address from that
        result, with ``timeout`` on the TCP connect and the handshake. There
        is no HTTP client, so redirects are not followed.

        When certificate verification fails, a second handshake to that same
        address reads the presented certificate with verification disabled.
        Those bytes are not trusted. They exist only so expiry, key size, and
        signature algorithm can still be reported. A DNS failure, timeout, or
        refused connection is raised for the caller to report as an error.
        """
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not infos:
            raise OSError(f"No address found for {host}.")

        connect_errors: list[OSError] = []
        for family, socktype, proto, _canon, sockaddr in infos:
            try:
                tcp = self._connect(family, socktype, proto, sockaddr, timeout)
            except OSError as exc:
                connect_errors.append(exc)
                continue
            pinned_ip = _peer_ip(tcp)
            try:
                verified = self._handshake(tcp, host, verify=True)
            except ssl.SSLError as exc:
                self._close(tcp)
                if not is_certificate_verification_failure(exc):
                    raise
                kind = classify_verification_failure(exc)
                inspected = self._read_presented_certificate(
                    host,
                    family,
                    socktype,
                    proto,
                    sockaddr,
                    pinned_ip,
                    timeout,
                )
                result: dict[str, Any] = {
                    "verification_ok": False,
                    "verification_failure": kind,
                    "verification_message": _short_verify_message(exc),
                    "peer_ip": pinned_ip,
                }
                if inspected is None:
                    result["certificate_source"] = "unavailable"
                    return result
                result.update(inspected)
                result["verification_ok"] = False
                result["verification_failure"] = kind
                result["certificate_source"] = "verification_disabled"
                result["peer_ip"] = pinned_ip
                return result
            verified_any: dict[str, Any] = dict(verified)
            verified_any["verification_ok"] = True
            verified_any["verification_failure"] = None
            verified_any["peer_ip"] = pinned_ip
            verified_any["certificate_source"] = "verified"
            return verified_any

        if connect_errors:
            raise connect_errors[-1]
        raise OSError(f"Could not connect to {host}:{port}.")

    def _read_presented_certificate(
        self,
        host: str,
        family: int,
        socktype: int,
        proto: int,
        sockaddr: Any,
        pinned_ip: str,
        timeout: float,
    ) -> dict[str, str] | None:
        """Second handshake. Same address, verification off, certificate bytes only.

        The name is not resolved again. If the peer IP is not the one the
        verified attempt already used, the bytes are discarded.
        """
        try:
            tcp = self._connect(family, socktype, proto, sockaddr, timeout)
        except OSError:
            return None
        try:
            if not _same_ip(_peer_ip(tcp), pinned_ip):
                return None
            return self._handshake(tcp, host, verify=False)
        except (OSError, ssl.SSLError, ValueError):
            return None
        finally:
            self._close(tcp)

    def _connect(
        self,
        family: int,
        socktype: int,
        proto: int,
        sockaddr: Any,
        timeout: float,
    ) -> socket.socket:
        tcp = socket.socket(family, socktype, proto)
        try:
            tcp.settimeout(timeout)
            tcp.connect(sockaddr)
        except Exception:
            self._close(tcp)
            raise
        return tcp

    def _handshake(self, tcp: socket.socket, host: str, *, verify: bool) -> dict[str, str]:
        context = self._build_ssl_context() if verify else self._build_inspection_context()
        try:
            tls = context.wrap_socket(tcp, server_hostname=host)
        except Exception:
            self._close(tcp)
            raise
        try:
            der_cert = tls.getpeercert(binary_form=True)
            if not der_cert:
                raise ValueError("Endpoint did not return a peer certificate.")
            cipher = tls.cipher()
            return {
                "certificate_pem": ssl.DER_cert_to_PEM_cert(der_cert),
                "tls_version": tls.version() or "unknown",
                "cipher_suite": cipher[0] if cipher else "unknown",
            }
        finally:
            self._close(tls)

    def _close(self, sock: object) -> None:
        close = getattr(sock, "close", None)
        if not callable(close):
            return
        try:
            close()
        except OSError:
            return

    def _build_ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        # Explicitly enforce modern TLS to satisfy secure transport policy.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def _build_inspection_context(self) -> ssl.SSLContext:
        """Context used only to read a certificate that already failed verification.

        Hostname checks and trust are off so the handshake can finish. Callers
        must not treat the result as authenticated. The socket is already
        pinned to the host and IP from the verified attempt. System trust
        anchors are not loaded.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def _assess(
        self, host: str, posture: dict[str, Any]
    ) -> tuple[list[CheckResult], dict[str, Any]]:
        verification_ok = bool(posture.get("verification_ok", True))
        failure = posture.get("verification_failure")
        kind: VerificationKind | None
        if verification_ok:
            kind = None
        elif failure in _TRUST_DETAILS:
            kind = failure
        else:
            kind = "other"

        cert = self._load_certificate(posture.get("certificate_pem"), required=verification_ok)
        source = posture.get("certificate_source")
        if source not in {"verified", "verification_disabled", "unavailable"}:
            if verification_ok:
                source = "verified"
            elif cert is not None:
                source = "verification_disabled"
            else:
                source = "unavailable"

        checks: list[CheckResult] = [self._trust_check(kind, posture)]
        hostname = self._hostname_check(host, cert, kind, verification_ok=verification_ok)
        if hostname is not None:
            checks.append(hostname)
        expiry = self._expiry_check(cert, kind)
        if expiry is not None:
            checks.append(expiry)

        tls_version = posture.get("tls_version")
        cipher_suite = posture.get("cipher_suite")
        if isinstance(tls_version, str) and tls_version:
            checks.append(
                CheckResult(
                    name="endpoint_tls_version_policy",
                    status="pass" if tls_version in {"TLSv1.2", "TLSv1.3"} else "fail",
                    details=f"Negotiated TLS version: {tls_version}.",
                    category="APISEC",
                    severity="high",
                    standard_reference="NIST SP 800-52r2",
                )
            )
        if isinstance(cipher_suite, str) and cipher_suite:
            checks.append(
                CheckResult(
                    name="endpoint_cipher_policy",
                    status="fail" if self._is_weak_cipher(cipher_suite) else "pass",
                    details=f"Negotiated cipher suite: {cipher_suite}.",
                    category="APISEC",
                    severity="high",
                    standard_reference="NIST SP 800-52r2",
                )
            )

        expires_in_days: int | None = None
        signature = None
        rsa_bits = None
        chain_posture = None
        if cert is not None:
            expires_in_days = (cert.not_valid_after_utc - datetime.now(UTC)).days
            signature = (
                cert.signature_hash_algorithm.name.lower()
                if cert.signature_hash_algorithm is not None
                else "unknown"
            )
            key = cert.public_key()
            rsa_bits = key.key_size if isinstance(key, rsa.RSAPublicKey) else None
            chain_posture = self._chain_posture(cert)
            checks.append(
                CheckResult(
                    name="endpoint_signature_algorithm",
                    status="fail" if "sha1" in signature or "md5" in signature else "pass",
                    details=f"Endpoint signature algorithm: {signature}.",
                    category="APISEC",
                    severity="critical",
                    standard_reference="OWASP API Security Top 10: API8",
                )
            )
            checks.append(
                CheckResult(
                    name="endpoint_rsa_key_size",
                    status="pass" if (rsa_bits is None or rsa_bits >= 2048) else "fail",
                    details=(
                        f"Endpoint RSA key size: {rsa_bits} bits."
                        if rsa_bits is not None
                        else "Endpoint key is non-RSA."
                    ),
                    category="APISEC",
                    severity="high",
                    standard_reference="OWASP API Security Top 10: API8",
                )
            )
            checks.append(
                CheckResult(
                    name="endpoint_chain_posture",
                    status="pass" if chain_posture["ok"] else "fail",
                    details=chain_posture["details"],
                    category="APISEC",
                    severity="high",
                    standard_reference="RFC 5280",
                )
            )

        data: dict[str, Any] = {
            "expires_in_days": expires_in_days,
            "tls_version": tls_version if isinstance(tls_version, str) else None,
            "cipher_suite": cipher_suite if isinstance(cipher_suite, str) else None,
            "signature_algorithm": signature,
            "rsa_key_size": rsa_bits,
            "chain_posture": chain_posture,
            "risk_level": self._risk(checks),
            "evaluation_status": "evaluated",
            "verification_failure": kind,
            "certificate_source": source,
            "certificate_inspection": (
                INSPECTION_DETAIL if source == "verification_disabled" else None
            ),
            "peer_ip": posture.get("peer_ip"),
        }
        return checks, data

    def _load_certificate(self, pem: object, *, required: bool) -> x509.Certificate | None:
        if not isinstance(pem, str) or not pem.strip():
            if required:
                raise ValueError("Endpoint did not return a peer certificate.")
            return None
        try:
            return x509.load_pem_x509_certificate(pem.encode("utf-8"))
        except ValueError:
            if required:
                raise
            return None

    def _trust_check(self, kind: VerificationKind | None, posture: dict[str, Any]) -> CheckResult:
        if kind is None:
            return CheckResult(
                name="endpoint_certificate_trust",
                status="pass",
                details="The endpoint certificate verified against the local trust store.",
                category="APISEC",
                severity="high",
                standard_reference="RFC 5280",
                actual_value="trusted",
            )
        message = posture.get("verification_message")
        detail_message = message if isinstance(message, str) else None
        return CheckResult(
            name="endpoint_certificate_trust",
            status="fail",
            details=trust_failure_detail(kind, detail_message),
            category="APISEC",
            severity="high",
            standard_reference="RFC 5280",
            actual_value=kind,
        )

    def _hostname_check(
        self,
        host: str,
        cert: x509.Certificate | None,
        kind: VerificationKind | None,
        *,
        verification_ok: bool,
    ) -> CheckResult | None:
        if verification_ok:
            return CheckResult(
                name="endpoint_hostname_match",
                status="pass",
                details=f"The certificate name matches {host}.",
                category="APISEC",
                severity="high",
                standard_reference="RFC 6125",
                actual_value=host,
            )
        if cert is not None:
            matches = self._name_matches(cert, host)
            return CheckResult(
                name="endpoint_hostname_match",
                status="pass" if matches else "fail",
                details=(
                    f"The name on the presented certificate matches {host}. "
                    "The certificate itself is not trusted."
                    if matches
                    else f"The name on the certificate does not match {host}."
                ),
                category="APISEC",
                severity="high",
                standard_reference="RFC 6125",
                actual_value=host,
            )
        if kind == "hostname_mismatch":
            return CheckResult(
                name="endpoint_hostname_match",
                status="fail",
                details=f"The name on the certificate does not match {host}.",
                category="APISEC",
                severity="high",
                standard_reference="RFC 6125",
                actual_value=host,
            )
        return None

    def _expiry_check(
        self, cert: x509.Certificate | None, kind: VerificationKind | None
    ) -> CheckResult | None:
        if cert is not None:
            expires_in_days = (cert.not_valid_after_utc - datetime.now(UTC)).days
            status: Status = "fail" if expires_in_days < 30 else "pass"
            if expires_in_days < 0:
                elapsed = abs(expires_in_days)
                unit = "day" if elapsed == 1 else "days"
                details = f"The endpoint certificate has expired ({elapsed} {unit} ago)."
            else:
                details = f"Certificate expires in {expires_in_days} days."
            return CheckResult(
                name="endpoint_certificate_expiry",
                status=status,
                details=details,
                category="APISEC",
                severity="high",
                standard_reference="OWASP API Security Top 10: API8",
                actual_value=expires_in_days,
            )
        if kind == "expired":
            return CheckResult(
                name="endpoint_certificate_expiry",
                status="fail",
                details="The endpoint certificate has expired.",
                category="APISEC",
                severity="high",
                standard_reference="OWASP API Security Top 10: API8",
                actual_value="expired",
            )
        return None

    def _name_matches(self, cert: x509.Certificate, host: str) -> bool:
        host_norm = host.lower().rstrip(".")
        try:
            ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(
                host_norm
            )
        except ValueError:
            ip = None
        san: x509.SubjectAlternativeName | None
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            san = None
        if ip is not None:
            if san is None:
                return False
            return ip in san.get_values_for_type(x509.IPAddress)
        names: list[str] = []
        if san is not None:
            names.extend(item.lower().rstrip(".") for item in san.get_values_for_type(x509.DNSName))
        if not names:
            for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                if isinstance(attr.value, str):
                    names.append(attr.value.lower().rstrip("."))
        return any(self._dns_matches(pattern, host_norm) for pattern in names)

    def _dns_matches(self, pattern: str, host: str) -> bool:
        if pattern == host:
            return True
        if pattern.startswith("*.") and pattern.count("*") == 1:
            suffix = pattern[1:]
            if not suffix or not host.endswith(suffix):
                return False
            prefix = host[: -len(suffix)]
            return bool(prefix) and "." not in prefix
        return False

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

    def _has_extension(self, cert: x509.Certificate, oid: x509.ObjectIdentifier) -> bool:
        try:
            cert.extensions.get_extension_for_oid(oid)
            return True
        except x509.ExtensionNotFound:
            return False

    def _risk(self, checks: list[CheckResult]) -> str:
        failed = [item for item in checks if item.status == "fail"]
        if any(item.name == "endpoint_certificate_trust" for item in failed):
            return "HIGH"
        if not failed:
            return "LOW"
        if any((item.severity or "").lower() == "critical" for item in failed):
            return "HIGH"
        return "MEDIUM"
