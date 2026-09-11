"""Render a policy profile as CP/CPS Section 7 documentation.

This module is the "single source of truth" claim made concrete: the prose a
reviewer reads is generated from the same YAML the CI gate enforces.

It previously hand-wrote a table of five parameters (validity, SAN, RSA bits,
prohibited algorithms, blocked suffixes) and ignored the ``rfc5280``, ``dcv``,
``issuance``, ``opa`` and ``crypto_transition`` sections entirely -- so the
module whose purpose was to prevent documentation drift was itself the drift.
It also re-hardcoded defaults (``.get("minimum_rsa_bits", 2048)``) that
duplicated the loader's defaults and could diverge from them.

Both are fixed: the parameter tables are driven by a declared section map, and
the enforced-control table is derived from ``CHECK_METADATA``, so a control
added to the validator appears in the documentation without a second edit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import yaml

from certguard.agents.policy_validator import CHECK_METADATA

#: (heading, [(label, policy path, formatter)]) for every enforced parameter.
#: Adding a policy key means adding a row here, and `test_policy_exporter.py`
#: asserts the export covers every control the validator can emit.
SECTION_MAP: tuple[tuple[str, tuple[tuple[str, str, str], ...]], ...] = (
    (
        "Validity",
        (
            ("Maximum validity period", "certificate.max_validity_days", "days"),
            ("Reject expired certificates", "certificate.reject_expired", "bool"),
            ("Reject not-yet-valid certificates", "certificate.reject_not_yet_valid", "bool"),
            ("Renewal warning window", "certificate.warn_if_expires_within_days", "days_or_off"),
        ),
    ),
    (
        "Identity",
        (
            ("Subject Alternative Name required", "certificate.require_san", "bool"),
            ("Internal names forbidden", "domains.forbid_internal_names", "bool"),
            ("Blocked name suffixes", "domains.blocked_suffixes", "list"),
        ),
    ),
    (
        "Key material",
        (
            ("Permitted key algorithms", "key.allowed_algorithms", "list"),
            ("Minimum RSA key size", "key.minimum_rsa_bits", "bits"),
            ("Minimum EC key size", "key.minimum_ec_bits", "bits"),
            ("Permitted EC curves", "key.allowed_ec_curves", "list"),
        ),
    ),
    (
        "Signature",
        (
            ("Prohibited hash algorithms", "signature.prohibited_algorithms", "list_upper"),
        ),
    ),
    (
        "Domain control validation",
        (
            ("DCV evidence required", "dcv.required", "bool"),
            ("Approved DCV methods", "dcv.allowed_methods", "list"),
            ("Maximum DCV evidence age", "dcv.max_age_days", "days"),
        ),
    ),
    (
        "RFC 5280 profile",
        (
            ("End-entity must not be a CA", "rfc5280.require_end_entity_not_ca", "bool"),
            ("Key usage profile enforced", "rfc5280.require_key_usage", "bool"),
            ("Required key usages", "rfc5280.required_key_usages", "list"),
            ("Subject Key Identifier required", "rfc5280.require_subject_key_identifier", "bool"),
            ("Authority Key Identifier required", "rfc5280.require_authority_key_identifier", "bool"),
            ("Permitted critical extensions", "rfc5280.allowed_critical_extensions", "list"),
            ("Issuer/subject path linkage", "rfc5280.require_path_issuer_subject_match", "bool"),
            ("AKI/SKI path linkage", "rfc5280.require_path_aki_ski_match", "bool"),
        ),
    ),
    (
        "Issuance controls",
        (
            ("HSM attestation required", "issuance.require_hsm_attestation", "bool"),
            ("Minimum FIPS 140 level", "issuance.min_fips_level", "plain"),
        ),
    ),
    (
        "Crypto transition overlay",
        (
            ("Overlay enabled", "crypto_transition.enabled", "bool"),
            ("Target maximum validity", "crypto_transition.target_max_validity_days", "days"),
            ("Target minimum RSA size", "crypto_transition.target_min_rsa_bits", "bits"),
            ("Approved signature hashes", "crypto_transition.approved_signature_algorithms", "list_upper"),
        ),
    ),
    (
        "External policy engine",
        (
            ("OPA/Rego gate enabled", "opa.enabled", "bool"),
            ("Rego policy file", "opa.policy_file", "code"),
        ),
    ),
    (
        "Pre-issuance linting",
        (
            ("zlint enabled", "lint.enable_zlint", "bool"),
            ("Failing lint severities", "lint.fail_severities", "list_upper"),
            ("openssl asn1parse enabled", "lint.enable_asn1parse", "bool"),
        ),
    ),
)

_FORMATTERS: dict[str, Callable[[Any], str]] = {
    "days": lambda v: f"`{v} days`" if v is not None else "`not set`",
    "days_or_off": lambda v: (
        "`disabled`" if not v else f"`{v} days`"
    ),
    "bits": lambda v: f"`{v} bits`" if v is not None else "`not set`",
    "bool": lambda v: f"`{'REQUIRED' if v else 'not enforced'}`",
    "plain": lambda v: f"`{v}`",
    "code": lambda v: f"`{v}`",
    "list": lambda v: (
        ", ".join(f"`{item}`" for item in v) if v else "`none`"
    ),
    "list_upper": lambda v: (
        ", ".join(f"`{str(item).upper()}`" for item in v) if v else "`none`"
    ),
}


def export_policy_to_markdown(
    policy_path: str | Path, output_path: str | Path | None = None
) -> str:
    path = Path(policy_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    metadata = data.get("metadata", {})
    terms = data.get("terms", [])

    lines: list[str] = [
        "# Certificate Policy Specification (CP/CPS Section 7)",
        "",
        f"> **Standard**: {metadata.get('standard', 'CA/Browser Forum Baseline Requirements')}",
        f"> **Policy Version**: {metadata.get('version', 'unknown')}",
        f"> **Policy Schema**: {metadata.get('policy_schema_version', 'unknown')}",
        f"> **Last Updated**: {metadata.get('last_updated', 'N/A')}",
        f"> **Source Profile**: `{path.name}`",
        "",
        "## 7.1 Certificate Profiles and Technical Controls",
        "",
        "This document is generated from the policy YAML that the CI gate evaluates.",
        "Prose and enforcement cannot diverge: both read the same file.",
        "",
    ]

    if terms:
        lines += [
            "### 7.1.1 Enforced Normative Terms",
            "",
            "| Rule ID | Title | Summary |",
            "| :--- | :--- | :--- |",
        ]
        for term in terms:
            lines.append(
                f"| **{term.get('id', 'N/A')}** | {term.get('title', 'Untitled Term')} "
                f"| {term.get('summary', '')} |"
            )
        lines.append("")

    lines += ["### 7.1.2 Technical Parameter Constraints", ""]
    for heading, rows in SECTION_MAP:
        lines += [
            f"#### {heading}",
            "",
            "| Parameter | Configured value |",
            "| :--- | :--- |",
        ]
        for label, dotted_path, formatter in rows:
            value = _get_nested(data, dotted_path)
            rendered = _FORMATTERS[formatter](value)
            lines.append(f"| {label} | {rendered} |")
        lines.append("")

    lines += [
        "### 7.1.3 Control Register",
        "",
        "Every control the policy engine can emit, with the standard it maps to.",
        "A control reported as `not_applicable` in a compliance report was defined",
        "but not enabled by the profile in force -- it was not assessed, and is",
        "never counted as a pass.",
        "",
        "| Control | Rule ID | Category | Severity | Standard reference |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for name in sorted(CHECK_METADATA):
        meta = CHECK_METADATA[name]
        lines.append(
            f"| `{name}` | {meta.get('rule_id', '')} | {meta.get('category', '')} "
            f"| {meta.get('severity', '')} | {meta.get('standard_reference', '')} |"
        )

    lines += [
        "",
        "---",
        "*Generated by the CertGuard Engine policy exporter from "
        f"`{path.name}`.*",
    ]

    markdown_content = "\n".join(lines)

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(markdown_content + "\n", encoding="utf-8")

    return markdown_content


def control_register_markdown() -> str:
    """Control table on its own, for embedding in the README coverage matrix."""
    lines = [
        "| Control | Rule ID | Category | Severity | Standard reference |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for name in sorted(CHECK_METADATA):
        meta = CHECK_METADATA[name]
        lines.append(
            f"| `{name}` | {meta.get('rule_id', '')} | {meta.get('category', '')} "
            f"| {meta.get('severity', '')} | {meta.get('standard_reference', '')} |"
        )
    return "\n".join(lines)


def _get_nested(payload: dict[str, Any], dotted_path: str) -> Any:
    current: Any = payload
    for part in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current
