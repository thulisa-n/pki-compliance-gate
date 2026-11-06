"""Offline trust-scope selection for CA/B Forum public-TLS controls.

``public`` assesses those controls. ``private`` reports them as
``not_applicable``. ``auto`` selects private only when a caller-supplied
chain verifies to one self-signed CA root and that root's SPKI SHA-256 is
absent from a caller-supplied public-trust root set.

No network. Missing, empty, or unverifiable inputs stay on ``public`` and
the decision records why.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

#: Details used when a public-TLS-only control is not assessed.
PUBLIC_TLS_NA_REASON = (
    "CA/B Forum Baseline Requirements apply to publicly-trusted TLS; trust scope is private"
)

_SCOPES = frozenset({"public", "private", "auto"})
_EXPLICIT_REASONS = {
    "public": (
        "trust scope is public; CA/B Forum Baseline Requirements for "
        "publicly-trusted TLS are assessed"
    ),
    "private": PUBLIC_TLS_NA_REASON,
}
_DOC_SUFFIXES = frozenset({".md", ".markdown", ".rst", ".json", ".yaml", ".yml"})
_HEX_HASH = re.compile(r"^(?:sha256:)?([0-9a-fA-F]{64})$")
_B64_HASH = re.compile(r"^sha256/([A-Za-z0-9+/=]+)$")


class TrustScopeInputError(ValueError):
    """A local chain or root set could not be used. Never means 'fetch it'."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class TrustScopeDecision:
    requested: str
    effective: str
    source: str
    reason: str
    public_roots: str | None = None
    chain: str | None = None
    root_spki_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "effective": self.effective,
            "source": self.source,
            "reason": self.reason,
            "public_roots": self.public_roots,
            "chain": self.chain,
            "root_spki_sha256": self.root_spki_sha256,
        }


def spki_sha256(certificate: x509.Certificate) -> str:
    """SHA-256 over the DER SubjectPublicKeyInfo. Lowercase hex."""
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def decide_trust_scope(
    policy: dict[str, Any],
    *,
    leaf_path: Path,
    cli_scope: str | None,
    cli_public_roots: str | None,
    chain_path: Path | None,
    evaluated_at: datetime,
    input_kind: str | None,
) -> TrustScopeDecision:
    """Resolve the trust scope for one evaluation. Fully local."""
    requested, source = requested_scope(cli_scope, policy)
    roots_path = configured_public_roots(cli_public_roots, policy)
    chain_display = None if chain_path is None else str(chain_path)

    if requested in {"public", "private"}:
        return TrustScopeDecision(
            requested=requested,
            effective=requested,
            source=source,
            reason=_EXPLICIT_REASONS[requested],
            public_roots=roots_path,
            chain=chain_display,
        )

    def as_public(detail: str, root: str | None = None) -> TrustScopeDecision:
        return TrustScopeDecision(
            requested="auto",
            effective="public",
            source=source,
            reason=f"trust scope auto resolved to public: {detail}",
            public_roots=roots_path,
            chain=chain_display,
            root_spki_sha256=root,
        )

    if input_kind == "csr":
        return as_public("a CSR has no certificate chain to a root")
    if chain_path is None:
        return as_public("no certificate chain was provided")
    if roots_path is None:
        return as_public("no public-trust root set was configured")

    try:
        pool = load_chain_certificates(Path(chain_path))
        anchors = load_public_trust_roots(Path(roots_path))
    except TrustScopeInputError as exc:
        return as_public(exc.reason)

    if not pool:
        return as_public("the certificate chain contained no certificates")
    if not anchors:
        return as_public("the public-trust root set contained no certificates or SPKI hashes")

    try:
        leaf = x509.load_pem_x509_certificate(Path(leaf_path).read_bytes())
    except (OSError, ValueError):
        return as_public("the leaf certificate could not be parsed")

    root, detail = verify_chain_to_root(leaf, pool, evaluated_at)
    if root is None:
        return as_public(detail or "the certificate chain does not verify to a root")

    digest = spki_sha256(root)
    if digest in anchors:
        return as_public(
            "the chain verifies to a root in the configured public-trust root set",
            root=digest,
        )
    return TrustScopeDecision(
        requested="auto",
        effective="private",
        source=source,
        reason=(
            "trust scope auto resolved to private: the chain verifies to a root "
            "that is not in the configured public-trust root set"
        ),
        public_roots=roots_path,
        chain=chain_display,
        root_spki_sha256=digest,
    )


def requested_scope(cli_scope: str | None, policy: dict[str, Any]) -> tuple[str, str]:
    """Return ``(scope, source)`` where source is cli, policy, or default.

    An explicit CLI value wins. Otherwise an explicit ``trust.scope`` in the
    policy file wins. Otherwise the scope is public.
    """
    if cli_scope is not None:
        if cli_scope not in _SCOPES:
            raise ValueError("trust scope must be one of public, private, auto")
        return cli_scope, "cli"
    configured = policy.get("trust", {}).get("scope", "public")
    if not isinstance(configured, str) or configured not in _SCOPES:
        raise ValueError("trust scope must be one of public, private, auto")
    explicit = bool(policy.get("_meta", {}).get("trust_scope_explicit"))
    if explicit:
        return configured, "policy"
    return "public", "default"


def configured_public_roots(cli_public_roots: str | None, policy: dict[str, Any]) -> str | None:
    """CLI path wins, including an explicit empty value. Else the policy path."""
    if cli_public_roots is not None:
        text = cli_public_roots.strip()
        return text or None
    raw = policy.get("trust", {}).get("public_roots", "")
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    return text or None


def load_chain_certificates(path: Path) -> list[x509.Certificate]:
    """Load PEM or DER certificates from a file or directory. No network."""
    certificates: list[x509.Certificate] = []
    for item in _input_files(path, "certificate chain"):
        data = _read_bytes(item, "certificate chain")
        certificates.extend(_certificates_from_bytes(data, "certificate chain"))
    return certificates


def load_public_trust_roots(path: Path) -> set[str]:
    """SPKI SHA-256 hex digests from root certificates and/or hash lists."""
    anchors: set[str] = set()
    for item in _input_files(path, "public-trust root set"):
        data = _read_bytes(item, "public-trust root set")
        certificates = _certificates_from_bytes(data, "public-trust root set")
        if certificates:
            anchors.update(spki_sha256(certificate) for certificate in certificates)
            continue
        anchors.update(_hashes_from_bytes(data))
    return anchors


def verify_chain_to_root(
    leaf: x509.Certificate,
    pool: list[x509.Certificate],
    evaluated_at: datetime,
) -> tuple[x509.Certificate | None, str | None]:
    """Return the trust anchor, or ``(None, reason)`` when the path is unclear.

    A path is accepted only when each step has one issuer, the signature
    verifies, AKI matches SKI when both are present, each issuer is a CA,
    and the terminal certificate is a self-signed CA. Issuer and root
    validity are checked at ``evaluated_at``. The leaf's own dates are not:
    expiry of the certificate under test is a separate control, unless that
    certificate is itself the trust anchor and it is outside its window
    while a distinct chain certificate was required to identify it.
    """
    if not pool:
        return None, "the certificate chain contained no certificates"

    if _is_self_signed(leaf):
        matches = [
            certificate
            for certificate in pool
            if certificate.subject == leaf.subject
            and spki_sha256(certificate) == spki_sha256(leaf)
            and _is_self_signed(certificate)
        ]
        chosen, detail = choose_issuer(matches)
        if chosen is None:
            if detail == "the certificate chain has more than one issuer candidate":
                return None, detail
            return None, "the provided chain does not link the leaf to a single root"
        if not _is_ca(chosen):
            return None, "the terminal certificate is not a CA"
        return chosen, None

    current = leaf
    seen: set[bytes] = {current.public_bytes(serialization.Encoding.DER)}
    for _ in range(len(pool) + 1):
        candidates = [
            issuer
            for issuer in pool
            if issuer.subject == current.issuer
            and _aki_compatible(current, issuer)
            and _signature_ok(current, issuer)
        ]
        chosen, detail = choose_issuer(candidates)
        if chosen is None:
            return None, detail
        der = chosen.public_bytes(serialization.Encoding.DER)
        if der in seen:
            return None, "the certificate chain contains a loop"
        if not _is_ca(chosen):
            if _is_self_signed(chosen):
                return None, "the terminal certificate is not a CA"
            return None, "a chain issuer is not a CA"
        if not _valid_at(chosen, evaluated_at):
            return None, "a certificate in the chain is outside its validity period"
        seen.add(der)
        if _is_self_signed(chosen):
            return chosen, None
        current = chosen
    return None, "the certificate chain does not verify to a root"


def choose_issuer(
    candidates: list[x509.Certificate],
) -> tuple[x509.Certificate | None, str | None]:
    """Pick the one issuer, collapsing duplicate certificates of the same key."""
    unique = _unique_by_spki(candidates)
    if len(unique) == 1:
        return unique[0], None
    if len(unique) > 1:
        return None, "the certificate chain has more than one issuer candidate"
    return None, "the certificate chain does not verify to a root"


def _unique_by_spki(certificates: list[x509.Certificate]) -> list[x509.Certificate]:
    seen: set[str] = set()
    unique: list[x509.Certificate] = []
    for certificate in certificates:
        digest = spki_sha256(certificate)
        if digest in seen:
            continue
        seen.add(digest)
        unique.append(certificate)
    return unique


def _input_files(path: Path, kind: str) -> list[Path]:
    if not path.exists():
        raise TrustScopeInputError(f"the {kind} path does not exist")
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise TrustScopeInputError(f"the {kind} path is not a file or directory")
    files: list[Path] = []
    for item in sorted(path.rglob("*")):
        if not item.is_file():
            continue
        relative = item.relative_to(path)
        if any(part.startswith(".") for part in relative.parts):
            continue
        if item.suffix.lower() in _DOC_SUFFIXES:
            continue
        files.append(item)
    return files


def _read_bytes(path: Path, kind: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise TrustScopeInputError(f"the {kind} could not be read") from exc


def _certificates_from_bytes(data: bytes, kind: str) -> list[x509.Certificate]:
    if b"-----BEGIN CERTIFICATE-----" in data:
        certificates: list[x509.Certificate] = []
        for block in data.split(b"-----END CERTIFICATE-----"):
            if b"-----BEGIN CERTIFICATE-----" not in block:
                continue
            start = block.index(b"-----BEGIN CERTIFICATE-----")
            pem = block[start:] + b"-----END CERTIFICATE-----\n"
            try:
                certificates.append(x509.load_pem_x509_certificate(pem))
            except ValueError as exc:
                raise TrustScopeInputError(f"the {kind} could not be parsed") from exc
        if not certificates:
            raise TrustScopeInputError(f"the {kind} could not be parsed")
        return certificates
    # Hash lists are ASCII and may start with '0' (byte 0x30), which is also
    # the DER SEQUENCE tag. Only non-ASCII payloads are attempted as DER.
    if _is_ascii(data):
        return []
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError as exc:
        raise TrustScopeInputError(f"the {kind} could not be parsed") from exc


def _is_ascii(data: bytes) -> bool:
    try:
        data.decode("ascii")
    except UnicodeDecodeError:
        return False
    return True


def _hashes_from_bytes(data: bytes) -> set[str]:
    if not data.strip():
        return set()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TrustScopeInputError("the public-trust root set could not be parsed") from exc
    hashes: set[str] = set()
    for line in text.splitlines():
        parsed = _hash_from_line(line)
        if parsed:
            hashes.add(parsed)
    return hashes


def _hash_from_line(line: str) -> str | None:
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    hex_match = _HEX_HASH.fullmatch(text)
    if hex_match:
        return hex_match.group(1).lower()
    b64_match = _B64_HASH.fullmatch(text)
    if b64_match is None:
        raise TrustScopeInputError("the public-trust root set could not be parsed")
    try:
        raw = base64.b64decode(b64_match.group(1), validate=True)
    except ValueError as exc:
        raise TrustScopeInputError("the public-trust root set could not be parsed") from exc
    if len(raw) != 32:
        raise TrustScopeInputError("the public-trust root set could not be parsed")
    return raw.hex()


def _is_self_signed(certificate: x509.Certificate) -> bool:
    return certificate.subject == certificate.issuer and _signature_ok(certificate, certificate)


def _signature_ok(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        child.verify_directly_issued_by(issuer)
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError):
        return False
    return True


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    return bool(extension.value.ca)


def _aki_compatible(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        key_identifier = child.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value.key_identifier
    except x509.ExtensionNotFound:
        return True
    if key_identifier is None:
        return True
    try:
        subject_key = issuer.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest
    except x509.ExtensionNotFound:
        return True
    return key_identifier == subject_key


def _valid_at(certificate: x509.Certificate, when: datetime) -> bool:
    instant = when if when.tzinfo is not None else when.replace(tzinfo=UTC)
    instant = instant.astimezone(UTC)
    return certificate.not_valid_before_utc <= instant <= certificate.not_valid_after_utc
