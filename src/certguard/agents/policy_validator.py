from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from certguard.agents.base import BaseAgent
from certguard.controls import CONTROL_POLICY_PATHS, registry_from_metadata
from certguard.models import AgentResult, CheckResult, Status

#: Controls that can be assessed from a CSR. Issued-certificate facts
#: (validity window, serial, SCT, path profile) are recorded as
#: ``not_applicable`` instead of guessed.
CSR_APPLICABLE_CONTROLS: frozenset[str] = frozenset(
    {
        "san_extension",
        "internal_domain_check",
        "key_algorithm_allowed",
        "rsa_key_size",
        "ec_key_size",
        "ec_curve_allowed",
        "signature_algorithm",
        "signature_algorithm_oid",
    }
)
CSR_NA_DETAILS = (
    "Not assessed on a CSR: this control requires an issued certificate."
)


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        timestamp = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return timestamp.replace(tzinfo=timestamp.tzinfo or UTC)


CHECK_METADATA: dict[str, dict[str, str]] = {
    "validity_days": {
        "rule_id": "CAB-BR-6.3.2",
        "category": "VALIDITY",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 6.3.2",
        "rationale": "Long validity windows increase exposure when private keys are compromised.",
        "recommendation": "Reissue certificate with validity at or below policy threshold.",
    },
    "certificate_not_expired": {
        "rule_id": "RFC-5280-4.1.2.5",
        "category": "VALIDITY",
        "severity": "critical",
        "standard_reference": "RFC 5280 4.1.2.5 / CA/B Forum BR 6.3.2",
        "rationale": "An expired certificate is rejected by relying parties and provides no assurance.",
        "recommendation": "Renew or replace the certificate before deploying it.",
    },
    "certificate_not_yet_valid": {
        "rule_id": "RFC-5280-4.1.2.5",
        "category": "VALIDITY",
        "severity": "high",
        "standard_reference": "RFC 5280 4.1.2.5",
        "rationale": "A certificate used before its notBefore time fails path validation.",
        "recommendation": "Wait until the notBefore time or reissue with a current validity window.",
    },
    "certificate_expiry_window": {
        "rule_id": "OPS-RENEWAL-WINDOW",
        "category": "VALIDITY",
        "severity": "low",
        "standard_reference": "Operational renewal policy",
        "rationale": "Certificates renewed inside a short window risk an outage if automation fails.",
        "recommendation": "Renew the certificate before it enters the configured warning window.",
    },
    "san_extension": {
        "rule_id": "RFC-5280-4.2.1.6",
        "category": "IDENTITY",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 7.1.4.2.1",
        "rationale": "Modern TLS clients rely on SAN for hostname validation.",
        "recommendation": "Issue certificate with SAN entries matching intended hostnames.",
    },
    "key_algorithm_allowed": {
        "rule_id": "CAB-BR-6.1.5",
        "category": "CRYPTOGRAPHY",
        "severity": "critical",
        "standard_reference": "CA/B Forum BR 6.1.5",
        "rationale": "Only approved public key algorithms carry assurance under the policy profile.",
        "recommendation": "Reissue using a public key algorithm permitted by policy.",
    },
    "rsa_key_size": {
        "rule_id": "CAB-BR-6.1.5",
        "category": "CRYPTOGRAPHY",
        "severity": "critical",
        "standard_reference": "CA/B Forum BR 6.1.5",
        "rationale": "Weak RSA keys reduce cryptographic strength and trust assurance.",
        "recommendation": "Generate key pair with RSA 2048+ before issuance.",
    },
    "ec_key_size": {
        "rule_id": "CAB-BR-6.1.5",
        "category": "CRYPTOGRAPHY",
        "severity": "critical",
        "standard_reference": "CA/B Forum BR 6.1.5",
        "rationale": "Undersized elliptic curve keys fall below the required security level.",
        "recommendation": "Generate an EC key of at least the policy minimum size (P-256 or stronger).",
    },
    "ec_curve_allowed": {
        "rule_id": "CAB-BR-6.1.5",
        "category": "CRYPTOGRAPHY",
        "severity": "critical",
        "standard_reference": "CA/B Forum BR 6.1.5",
        "rationale": "Only NIST P-256, P-384 and P-521 are permitted for publicly trusted ECDSA keys.",
        "recommendation": "Reissue using an approved named curve (secp256r1, secp384r1, secp521r1).",
    },
    "signature_algorithm": {
        "rule_id": "CAB-BR-7.1.3",
        "category": "CRYPTOGRAPHY",
        "severity": "critical",
        "standard_reference": "CA/B Forum BR 7.1.3",
        "rationale": "Deprecated hash algorithms can be vulnerable to collision attacks.",
        "recommendation": "Use SHA-256 or stronger signature algorithm.",
    },
    "signature_algorithm_oid": {
        "rule_id": "CAB-BR-7.1.3.2",
        "category": "CRYPTOGRAPHY",
        "severity": "critical",
        "standard_reference": "CA/B Forum BR 7.1.3.2",
        "rationale": "The Baseline Requirements constrain the signature AlgorithmIdentifier, not just the digest name.",
        "recommendation": "Sign with an allowed algorithm OID such as sha256WithRSAEncryption or ecdsa-with-SHA256.",
    },
    "serial_entropy": {
        "rule_id": "CAB-BR-7.1",
        "category": "IDENTITY",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 7.1",
        "rationale": "Predictable serial numbers enable collision and tracking attacks; at least 64 bits of entropy is required.",
        "recommendation": "Issue certificates with a cryptographically random serial of at least 64 bits.",
    },
    "sct_presence": {
        "rule_id": "CAB-BR-CT-SCT",
        "category": "TRANSPARENCY",
        "severity": "high",
        "standard_reference": "Certificate Transparency / CA/B Forum BR",
        "rationale": "Browser trust requires embedded Signed Certificate Timestamps.",
        "recommendation": "Submit the precertificate to CT logs and embed the required SCTs.",
    },
    "extended_key_usage": {
        "rule_id": "CAB-BR-7.1.2",
        "category": "IDENTITY",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 7.1.2 / RFC 5280 4.2.1.12",
        "rationale": "EKU binds a certificate to an intended purpose such as TLS server authentication.",
        "recommendation": "Include the required extendedKeyUsage values for the certificate profile.",
    },
    "internal_domain_check": {
        "rule_id": "CAB-BR-7.1.4.2.1",
        "category": "POLICY",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 7.1.4.2.1",
        "rationale": "Internal names are not valid for publicly trusted certificates.",
        "recommendation": "Replace internal SAN values with public DNS names.",
    },
    "dcv_method": {
        "rule_id": "CAB-BR-3.2.2.4",
        "category": "DCV",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 3.2.2.4",
        "rationale": "Domain Control Validation must use approved methods before issuance.",
        "recommendation": "Use an approved DCV method and record validation evidence.",
    },
    "dcv_recency": {
        "rule_id": "CAB-BR-4.2.1",
        "category": "DCV",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 4.2.1",
        "rationale": "Stale domain validation evidence can invalidate issuance decisions.",
        "recommendation": "Re-run DCV within the allowed validation window.",
    },
    "rfc5280_end_entity_ca": {
        "rule_id": "RFC-5280-4.2.1.9",
        "category": "RFC5280",
        "severity": "high",
        "standard_reference": "RFC 5280 4.2.1.9",
        "rationale": "Subscriber certificates should not present CA basic constraints.",
        "recommendation": "Issue end-entity certificate with BasicConstraints CA set to FALSE.",
    },
    "rfc5280_key_usage_profile": {
        "rule_id": "RFC-5280-4.2.1.3",
        "category": "RFC5280",
        "severity": "high",
        "standard_reference": "RFC 5280 4.2.1.3",
        "rationale": "Key usage extensions must align with intended certificate purpose.",
        "recommendation": "Set key usage extension to include required subscriber usages.",
    },
    "rfc5280_subject_key_identifier": {
        "rule_id": "RFC-5280-4.2.1.2",
        "category": "RFC5280",
        "severity": "medium",
        "standard_reference": "RFC 5280 4.2.1.2",
        "rationale": "SKI helps bind subject keys to certificate lifecycle and chain processing.",
        "recommendation": "Include Subject Key Identifier extension for leaf profile consistency.",
    },
    "rfc5280_authority_key_identifier": {
        "rule_id": "RFC-5280-4.2.1.1",
        "category": "RFC5280",
        "severity": "medium",
        "standard_reference": "RFC 5280 4.2.1.1",
        "rationale": "AKI supports robust issuer key linkage during path validation.",
        "recommendation": "Include Authority Key Identifier extension for issuer linkage.",
    },
    "rfc5280_critical_extension_profile": {
        "rule_id": "RFC-5280-4.2",
        "category": "RFC5280",
        "severity": "high",
        "standard_reference": "RFC 5280 4.2",
        "rationale": "Unexpected critical extensions can break relying-party validation behavior.",
        "recommendation": "Restrict critical extensions to an approved extension profile.",
    },
    "rfc5280_path_issuer_subject_match": {
        "rule_id": "RFC-5280-6",
        "category": "RFC5280",
        "severity": "high",
        "standard_reference": "RFC 5280 6.1",
        "rationale": "Issuer and subject linkage is required for path construction.",
        "recommendation": "Provide the issuing certificate and validate issuer-subject linkage.",
    },
    "rfc5280_path_aki_ski_match": {
        "rule_id": "RFC-5280-4.2.1.1",
        "category": "RFC5280",
        "severity": "medium",
        "standard_reference": "RFC 5280 4.2.1.1",
        "rationale": "AKI/SKI linkage improves deterministic path validation.",
        "recommendation": "Ensure leaf AKI matches issuer SKI.",
    },
    "issuance_hsm_attestation": {
        "rule_id": "PKCS11-HSM-ATTESTATION",
        "category": "ISSUANCE",
        "severity": "high",
        "standard_reference": "PKCS#11 / FIPS operations",
        "rationale": "Key custody controls require evidence of hardware-backed issuance operations.",
        "recommendation": "Provide issuance attestation indicating HSM-backed key operations.",
    },
    "issuance_fips_level": {
        "rule_id": "FIPS-140-CONTROL",
        "category": "ISSUANCE",
        "severity": "medium",
        "standard_reference": "FIPS 140-2/140-3",
        "rationale": "Cryptographic module assurance levels are key audit controls.",
        "recommendation": "Provide attested FIPS level meeting minimum policy requirement.",
    },
    "crypto_transition_validity_target": {
        "rule_id": "CRYPTO-AGILITY-VALIDITY",
        "category": "CRYPTO-TRANSITION",
        "severity": "high",
        "standard_reference": "Crypto transition readiness profile",
        "rationale": "Short-lived certificate profiles reduce exposure and improve rotation agility.",
        "recommendation": "Reduce certificate validity to transition target or lower.",
    },
    "crypto_transition_rsa_target": {
        "rule_id": "CRYPTO-AGILITY-RSA",
        "category": "CRYPTO-TRANSITION",
        "severity": "medium",
        "standard_reference": "Crypto transition readiness profile",
        "rationale": "Stronger key sizes improve resilience during algorithm transition periods.",
        "recommendation": "Issue RSA certificates at or above the transition RSA key target.",
    },
    "crypto_transition_signature_hash": {
        "rule_id": "CRYPTO-AGILITY-HASH",
        "category": "CRYPTO-TRANSITION",
        "severity": "high",
        "standard_reference": "Crypto transition readiness profile",
        "rationale": "Approved signature hashes reduce risk from weak or deprecated digests.",
        "recommendation": "Use signature hash algorithms from the approved transition allowlist.",
    },
}

CONTROLS = registry_from_metadata(CHECK_METADATA, CONTROL_POLICY_PATHS)
#: Every control this agent can emit. Used by the CP/CPS exporter and by
#: tests that assert documentation covers the full enforced control set.
ALL_CONTROL_NAMES: tuple[str, ...] = tuple(control.name for control in CONTROLS)


class PolicyValidatorAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="policy_validator_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        policy = context["policy"]
        parser_data = context["parser_data"]
        dcv_attestation = context.get("dcv_attestation")
        issuer_parser_data = context.get("issuer_parser_data")
        issuance_attestation = context.get("issuance_attestation")

        checks: list[CheckResult] = []
        checks.extend(self._validity_checks(policy, parser_data))
        checks.extend(self._san_checks(policy, parser_data))
        checks.extend(self._key_checks(policy, parser_data))
        checks.extend(self._signature_checks(policy, parser_data))
        checks.extend(self._internal_domain_checks(policy, parser_data))
        checks.extend(self._dcv_checks(policy, dcv_attestation))
        checks.extend(self._rfc5280_checks(policy, parser_data, issuer_parser_data))
        checks.extend(self._issuance_checks(policy, issuance_attestation))
        checks.extend(self._crypto_transition_checks(policy, parser_data))
        checks.extend(self._browser_trust_checks(policy, parser_data))

        if parser_data.get("input_kind") == "csr":
            checks = [
                check
                if check.name in CSR_APPLICABLE_CONTROLS
                else self._na(check.name, CSR_NA_DETAILS)
                for check in checks
            ]

        # A run succeeds when nothing failed. Controls that policy did not
        # enable are not_applicable and must not count against the run, but
        # neither may they be reported as passes.
        success = not any(check.status == "fail" for check in checks)
        return AgentResult(agent=self.name, success=success, checks=checks)

    # ---------------------------------------------------------------- validity

    def _validity_checks(
        self, policy: dict[str, Any], parser_data: dict[str, Any]
    ) -> list[CheckResult]:
        cert_cfg = policy["certificate"]
        checks: list[CheckResult] = []

        max_validity = cert_cfg["max_validity_days"]
        exact_validity_days = self._exact_validity_days(parser_data)
        checks.append(
            self._check(
                "validity_days",
                exact_validity_days is not None
                and exact_validity_days <= max_validity,
                (
                    f"Certificate validity is {exact_validity_days:g} days "
                    f"(max {max_validity})"
                    if exact_validity_days is not None
                    else "Certificate validity value is missing."
                ),
                policy_value=max_validity,
                actual_value=exact_validity_days,
            )
        )

        not_after = parser_data.get("not_after")
        evaluated_at = parser_data.get("evaluated_at")
        days_until_expiry = parser_data.get("days_until_expiry")
        evaluation_time = _parse_timestamp(evaluated_at) or datetime.now(UTC)
        parsed_not_after = _parse_timestamp(not_after)
        parsed_not_before = _parse_timestamp(parser_data.get("not_before"))

        raw_expired = parser_data.get("is_expired")
        if isinstance(raw_expired, bool):
            is_expired: bool | None = raw_expired
        elif parsed_not_after is not None:
            is_expired = parsed_not_after < evaluation_time
        else:
            is_expired = None

        raw_not_yet = parser_data.get("is_not_yet_valid")
        if isinstance(raw_not_yet, bool):
            not_yet: bool | None = raw_not_yet
        elif parsed_not_before is not None:
            not_yet = parsed_not_before > evaluation_time
        else:
            not_yet = None

        if cert_cfg["reject_expired"]:
            if is_expired is True and isinstance(days_until_expiry, int):
                expiry_details = (
                    f"Certificate expired on {not_after} "
                    f"({abs(days_until_expiry)} days ago as at {evaluated_at})."
                )
            elif is_expired is True:
                expiry_details = f"Certificate expired on {not_after}."
            elif is_expired is None:
                expiry_details = (
                    "Certificate expiry state cannot be established from parser evidence."
                )
            else:
                expiry_details = (
                    f"Certificate is within its validity window; expires {not_after}."
                )
            checks.append(
                self._check(
                    "certificate_not_expired",
                    is_expired is False,
                    expiry_details,
                    policy_value="notAfter must be in the future",
                    actual_value=not_after,
                )
            )
        else:
            checks.append(
                self._na(
                    "certificate_not_expired",
                    "Expiry enforcement disabled by policy (certificate.reject_expired=false).",
                    policy_value=False,
                    actual_value=not_after,
                )
            )

        if cert_cfg["reject_not_yet_valid"]:
            if not_yet is True:
                not_yet_details = (
                    f"Certificate is not valid until {parser_data.get('not_before')}."
                )
            elif not_yet is None:
                not_yet_details = (
                    "Certificate start-of-validity state cannot be established "
                    "from parser evidence."
                )
            else:
                not_yet_details = "Certificate notBefore time has passed."
            checks.append(
                self._check(
                    "certificate_not_yet_valid",
                    not_yet is False,
                    not_yet_details,
                    policy_value="notBefore must be in the past",
                    actual_value=parser_data.get("not_before"),
                )
            )
        else:
            checks.append(
                self._na(
                    "certificate_not_yet_valid",
                    "notBefore enforcement disabled by policy "
                    "(certificate.reject_not_yet_valid=false).",
                    policy_value=False,
                    actual_value=parser_data.get("not_before"),
                )
            )

        warn_days = cert_cfg["warn_if_expires_within_days"]
        if warn_days > 0 and (is_expired is True or not_yet is True):
            checks.append(
                self._na(
                    "certificate_expiry_window",
                    "Renewal-window guidance does not apply outside the certificate validity window.",
                    policy_value=warn_days,
                    actual_value=days_until_expiry,
                )
            )
        elif warn_days > 0:
            inside_window = (
                isinstance(days_until_expiry, int) and days_until_expiry <= warn_days
            )
            checks.append(
                self._check(
                    "certificate_expiry_window",
                    not inside_window,
                    (
                        f"Certificate expires in {days_until_expiry} days, inside the "
                        f"{warn_days}-day renewal window."
                        if inside_window
                        else f"Certificate expires in {days_until_expiry} days, outside the "
                        f"{warn_days}-day renewal window."
                    ),
                    policy_value=warn_days,
                    actual_value=days_until_expiry,
                )
            )
        else:
            checks.append(
                self._na(
                    "certificate_expiry_window",
                    "Renewal window warning disabled by policy "
                    "(certificate.warn_if_expires_within_days=0).",
                    policy_value=0,
                    actual_value=days_until_expiry,
                )
            )

        return checks

    def _san_checks(
        self, policy: dict[str, Any], parser_data: dict[str, Any]
    ) -> list[CheckResult]:
        require_san = policy["certificate"]["require_san"]
        san_dns = parser_data["san_dns"]
        if not require_san:
            return [
                self._na(
                    "san_extension",
                    "SAN requirement disabled by policy (certificate.require_san=false).",
                    policy_value=False,
                    actual_value=bool(san_dns),
                )
            ]
        return [
            self._check(
                "san_extension",
                bool(san_dns),
                "SAN extension present" if san_dns else "SAN extension missing",
                policy_value=require_san,
                actual_value=bool(san_dns),
            )
        ]

    # --------------------------------------------------------------------- key

    def _key_checks(
        self, policy: dict[str, Any], parser_data: dict[str, Any]
    ) -> list[CheckResult]:
        key_cfg = policy["key"]
        algorithm = self._key_algorithm(parser_data)
        size_bits = self._key_size_bits(parser_data)
        curve = parser_data.get("ec_curve")
        allowed_algorithms = {
            value.strip().lower() for value in key_cfg["allowed_algorithms"]
        }

        checks: list[CheckResult] = [
            self._check(
                "key_algorithm_allowed",
                algorithm in allowed_algorithms,
                (
                    f"Public key algorithm '{algorithm}' is permitted."
                    if algorithm in allowed_algorithms
                    else f"Public key algorithm '{algorithm}' is not permitted by policy."
                ),
                policy_value=sorted(allowed_algorithms),
                actual_value=algorithm,
            )
        ]

        min_rsa_bits = key_cfg["minimum_rsa_bits"]
        if algorithm == "rsa":
            checks.append(
                self._check(
                    "rsa_key_size",
                    isinstance(size_bits, int) and size_bits >= min_rsa_bits,
                    f"RSA key size is {size_bits} bits (min {min_rsa_bits})",
                    policy_value=min_rsa_bits,
                    actual_value=size_bits,
                )
            )
        else:
            checks.append(
                self._na(
                    "rsa_key_size",
                    f"Key algorithm is '{algorithm}'; RSA key size check not applicable.",
                    policy_value=min_rsa_bits,
                    actual_value=None,
                )
            )

        min_ec_bits = key_cfg["minimum_ec_bits"]
        allowed_curves = {
            value.strip().lower() for value in key_cfg["allowed_ec_curves"]
        }
        if algorithm == "ec":
            checks.append(
                self._check(
                    "ec_key_size",
                    isinstance(size_bits, int) and size_bits >= min_ec_bits,
                    f"EC key size is {size_bits} bits (min {min_ec_bits})",
                    policy_value=min_ec_bits,
                    actual_value=size_bits,
                )
            )
            checks.append(
                self._check(
                    "ec_curve_allowed",
                    isinstance(curve, str) and curve.lower() in allowed_curves,
                    (
                        f"EC curve '{curve}' is permitted."
                        if isinstance(curve, str) and curve.lower() in allowed_curves
                        else f"EC curve '{curve or 'unknown'}' is not permitted by policy."
                    ),
                    policy_value=sorted(allowed_curves),
                    actual_value=curve,
                )
            )
        else:
            checks.append(
                self._na(
                    "ec_key_size",
                    f"Key algorithm is '{algorithm}'; EC key size check not applicable.",
                    policy_value=min_ec_bits,
                    actual_value=None,
                )
            )
            checks.append(
                self._na(
                    "ec_curve_allowed",
                    f"Key algorithm is '{algorithm}'; EC curve check not applicable.",
                    policy_value=sorted(allowed_curves),
                    actual_value=None,
                )
            )

        return checks

    def _signature_checks(
        self, policy: dict[str, Any], parser_data: dict[str, Any]
    ) -> list[CheckResult]:
        forbidden_algorithms = {
            algo.lower() for algo in policy["signature"]["prohibited_algorithms"]
        }
        signature_hash = str(parser_data["signature_algorithm"]).lower()
        signature_name = str(parser_data.get("signature_algorithm_name", signature_hash))
        # Match on both the bare digest and the full algorithm identifier so a
        # policy can prohibit either "sha1" or "sha1withrsaencryption".
        offending = sorted(
            value
            for value in forbidden_algorithms
            if value == signature_hash or value in signature_name
        )
        checks = [
            self._check(
                "signature_algorithm",
                not offending,
                (
                    f"Signature algorithm is {signature_hash} ({signature_name})"
                    if not offending
                    else f"Signature algorithm is {signature_hash} ({signature_name}); "
                    f"prohibited: {', '.join(offending)}"
                ),
                policy_value=sorted(forbidden_algorithms),
                actual_value=signature_hash,
            )
        ]

        allowed_oids = {
            str(value).strip()
            for value in policy["signature"].get("allowed_oids") or []
            if str(value).strip()
        }
        actual_oid = str(parser_data.get("signature_algorithm_oid") or "")
        if not allowed_oids:
            checks.append(
                self._na(
                    "signature_algorithm_oid",
                    "Signature OID allowlist disabled by policy (signature.allowed_oids is empty).",
                    policy_value=[],
                    actual_value=actual_oid or None,
                )
            )
        else:
            checks.append(
                self._check(
                    "signature_algorithm_oid",
                    actual_oid in allowed_oids,
                    (
                        f"Signature algorithm OID {actual_oid} is permitted."
                        if actual_oid in allowed_oids
                        else f"Signature algorithm OID {actual_oid or 'missing'} is not in the policy allowlist."
                    ),
                    policy_value=sorted(allowed_oids),
                    actual_value=actual_oid or None,
                )
            )
        return checks

    def _browser_trust_checks(
        self, policy: dict[str, Any], parser_data: dict[str, Any]
    ) -> list[CheckResult]:
        cert_cfg = policy["certificate"]
        checks: list[CheckResult] = []

        min_serial_bits = cert_cfg["min_serial_bits"]
        serial_bits = parser_data.get("serial_number_bits")
        if min_serial_bits <= 0:
            checks.append(
                self._na(
                    "serial_entropy",
                    "Serial-entropy check disabled by policy (certificate.min_serial_bits=0).",
                    policy_value=0,
                    actual_value=serial_bits,
                )
            )
        else:
            enough = isinstance(serial_bits, int) and serial_bits >= min_serial_bits
            checks.append(
                self._check(
                    "serial_entropy",
                    enough,
                    (
                        f"Serial number has {serial_bits} bits (min {min_serial_bits})."
                        if isinstance(serial_bits, int)
                        else "Serial number bit length is missing from parser evidence."
                    ),
                    policy_value=min_serial_bits,
                    actual_value=serial_bits,
                )
            )

        if not cert_cfg["require_sct"]:
            checks.append(
                self._na(
                    "sct_presence",
                    "SCT presence check disabled by policy (certificate.require_sct=false).",
                    policy_value=False,
                    actual_value=parser_data.get("sct_count"),
                )
            )
        else:
            required = cert_cfg["min_sct_count"]
            actual = parser_data.get("sct_count")
            enough = isinstance(actual, int) and actual >= required
            checks.append(
                self._check(
                    "sct_presence",
                    enough,
                    (
                        f"Certificate embeds {actual} SCT(s) (min {required})."
                        if isinstance(actual, int)
                        else "SCT count is missing from parser evidence."
                    ),
                    policy_value=required,
                    actual_value=actual,
                )
            )

        if not cert_cfg["require_eku"]:
            checks.append(
                self._na(
                    "extended_key_usage",
                    "EKU profile check disabled by policy (certificate.require_eku=false).",
                    policy_value=cert_cfg["required_ekus"],
                    actual_value=parser_data.get("extended_key_usage"),
                )
            )
        else:
            required = {str(value).strip() for value in cert_cfg["required_ekus"] if str(value).strip()}
            actual = {str(value).strip() for value in parser_data.get("extended_key_usage") or []}
            missing = sorted(required - actual)
            checks.append(
                self._check(
                    "extended_key_usage",
                    not missing,
                    (
                        "Certificate includes every required EKU."
                        if not missing
                        else f"Certificate is missing required EKU values: {', '.join(missing)}."
                    ),
                    policy_value=sorted(required),
                    actual_value=sorted(actual),
                )
            )
        return checks

    # --------------------------------------------------------------------- dcv

    def _dcv_checks(
        self, policy: dict[str, Any], dcv_attestation: dict[str, Any] | None
    ) -> list[CheckResult]:
        dcv_cfg = policy["dcv"]
        if not dcv_cfg["required"]:
            return [
                self._na(
                    "dcv_method",
                    "DCV checks disabled by policy (dcv.required=false).",
                    policy_value=dcv_cfg["allowed_methods"],
                    actual_value=None,
                ),
                self._na(
                    "dcv_recency",
                    "DCV recency checks disabled by policy (dcv.required=false).",
                    policy_value=dcv_cfg["max_age_days"],
                    actual_value=None,
                ),
            ]

        if not isinstance(dcv_attestation, dict):
            return [
                self._check(
                    "dcv_method",
                    False,
                    "DCV attestation is required but missing.",
                    policy_value=dcv_cfg["allowed_methods"],
                    actual_value=None,
                ),
                self._check(
                    "dcv_recency",
                    False,
                    "DCV attestation timestamp is required but missing.",
                    policy_value=dcv_cfg["max_age_days"],
                    actual_value=None,
                ),
            ]

        method = str(dcv_attestation.get("method", "")).strip().lower()
        allowed = {value.lower() for value in dcv_cfg["allowed_methods"]}
        method_ok = method in allowed if allowed else False

        recency_ok, recency_details, actual_age = self._dcv_recency(
            dcv_attestation.get("validated_at"), dcv_cfg["max_age_days"]
        )

        return [
            self._check(
                "dcv_method",
                method_ok,
                (
                    f"DCV method '{method}' accepted."
                    if method_ok
                    else f"DCV method '{method or 'missing'}' not allowed."
                ),
                policy_value=sorted(allowed),
                actual_value=method or None,
            ),
            self._check(
                "dcv_recency",
                recency_ok,
                recency_details,
                policy_value=dcv_cfg["max_age_days"],
                actual_value=actual_age,
            ),
        ]

    def _dcv_recency(
        self, validated_at: Any, max_age_days: int
    ) -> tuple[bool, str, int | None]:
        if not isinstance(validated_at, str) or not validated_at.strip():
            return False, "DCV attestation missing validated_at timestamp.", None
        try:
            timestamp = datetime.fromisoformat(validated_at.replace("Z", "+00:00"))
        except ValueError:
            return False, "DCV validated_at timestamp is not ISO-8601.", None

        now = datetime.now(UTC)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        age_days = (now - timestamp.astimezone(UTC)).days
        if age_days < 0:
            return False, "DCV validated_at is in the future.", age_days
        if age_days <= max_age_days:
            return (
                True,
                f"DCV attestation age is {age_days} days (max {max_age_days}).",
                age_days,
            )
        return (
            False,
            f"DCV attestation age is {age_days} days (max {max_age_days}).",
            age_days,
        )

    # ----------------------------------------------------------------- rfc5280

    def _rfc5280_checks(
        self,
        policy: dict[str, Any],
        parser_data: dict[str, Any],
        issuer_parser_data: dict[str, Any] | None,
    ) -> list[CheckResult]:
        rfc_cfg = policy["rfc5280"]
        checks: list[CheckResult] = []

        if rfc_cfg["require_end_entity_not_ca"]:
            basic_ca = parser_data.get("basic_constraints_ca")
            checks.append(
                self._check(
                    "rfc5280_end_entity_ca",
                    basic_ca is False,
                    (
                        "BasicConstraints CA is FALSE."
                        if basic_ca is False
                        else "BasicConstraints CA is TRUE or missing for end-entity profile."
                    ),
                    policy_value=False,
                    actual_value=basic_ca,
                )
            )
        else:
            checks.append(
                self._na(
                    "rfc5280_end_entity_ca",
                    "RFC 5280 end-entity CA check disabled by policy.",
                    policy_value=False,
                    actual_value=parser_data.get("basic_constraints_ca"),
                )
            )

        if rfc_cfg["require_key_usage"]:
            required = {value.lower() for value in rfc_cfg["required_key_usages"]}
            actual = {value.lower() for value in parser_data.get("key_usage", [])}
            missing = sorted(required - actual)
            checks.append(
                self._check(
                    "rfc5280_key_usage_profile",
                    not missing,
                    (
                        "Required key usage flags are present."
                        if not missing
                        else f"Missing key usage flags: {', '.join(missing)}"
                    ),
                    policy_value=sorted(required),
                    actual_value=sorted(actual),
                )
            )
        else:
            checks.append(
                self._na(
                    "rfc5280_key_usage_profile",
                    "RFC 5280 key usage profile check disabled by policy.",
                    policy_value=sorted(
                        value.lower() for value in rfc_cfg["required_key_usages"]
                    ),
                    actual_value=sorted(
                        value.lower() for value in parser_data.get("key_usage", [])
                    ),
                )
            )

        if rfc_cfg["require_subject_key_identifier"]:
            has_ski = bool(parser_data.get("has_subject_key_identifier"))
            checks.append(
                self._check(
                    "rfc5280_subject_key_identifier",
                    has_ski,
                    "Subject Key Identifier extension present."
                    if has_ski
                    else "Subject Key Identifier extension missing.",
                    policy_value=True,
                    actual_value=has_ski,
                )
            )
        else:
            checks.append(
                self._na(
                    "rfc5280_subject_key_identifier",
                    "RFC 5280 SKI check disabled by policy.",
                    policy_value=False,
                    actual_value=bool(parser_data.get("has_subject_key_identifier")),
                )
            )

        if rfc_cfg["require_authority_key_identifier"]:
            has_aki = bool(parser_data.get("has_authority_key_identifier"))
            checks.append(
                self._check(
                    "rfc5280_authority_key_identifier",
                    has_aki,
                    "Authority Key Identifier extension present."
                    if has_aki
                    else "Authority Key Identifier extension missing.",
                    policy_value=True,
                    actual_value=has_aki,
                )
            )
        else:
            checks.append(
                self._na(
                    "rfc5280_authority_key_identifier",
                    "RFC 5280 AKI check disabled by policy.",
                    policy_value=False,
                    actual_value=bool(parser_data.get("has_authority_key_identifier")),
                )
            )

        allowed_critical = {
            value.strip()
            for value in rfc_cfg["allowed_critical_extensions"]
            if value.strip()
        }
        critical_oids = {
            value.strip()
            for value in parser_data.get("critical_extension_oids", [])
            if value
        }
        if allowed_critical:
            unknown_critical = sorted(critical_oids - allowed_critical)
            checks.append(
                self._check(
                    "rfc5280_critical_extension_profile",
                    not unknown_critical,
                    (
                        "Critical extensions align with policy profile."
                        if not unknown_critical
                        else f"Unexpected critical extensions: {', '.join(unknown_critical)}"
                    ),
                    policy_value=sorted(allowed_critical),
                    actual_value=sorted(critical_oids),
                )
            )
        else:
            checks.append(
                self._na(
                    "rfc5280_critical_extension_profile",
                    "Critical extension profile linting disabled by policy "
                    "(rfc5280.allowed_critical_extensions is empty).",
                    policy_value=[],
                    actual_value=sorted(critical_oids),
                )
            )

        if rfc_cfg["require_path_issuer_subject_match"]:
            if not isinstance(issuer_parser_data, dict):
                checks.append(
                    self._check(
                        "rfc5280_path_issuer_subject_match",
                        False,
                        "Issuer certificate parser data missing for path linkage check.",
                        policy_value=True,
                        actual_value=False,
                    )
                )
            else:
                issuer_match = parser_data.get("issuer") == issuer_parser_data.get(
                    "subject"
                )
                checks.append(
                    self._check(
                        "rfc5280_path_issuer_subject_match",
                        issuer_match,
                        "Leaf issuer matches issuer certificate subject."
                        if issuer_match
                        else "Leaf issuer does not match provided issuer certificate subject.",
                        policy_value=True,
                        actual_value=issuer_match,
                    )
                )
        else:
            checks.append(
                self._na(
                    "rfc5280_path_issuer_subject_match",
                    "RFC 5280 issuer-subject path check disabled by policy.",
                    policy_value=False,
                    actual_value=None,
                )
            )

        if rfc_cfg["require_path_aki_ski_match"]:
            if not isinstance(issuer_parser_data, dict):
                checks.append(
                    self._check(
                        "rfc5280_path_aki_ski_match",
                        False,
                        "Issuer certificate parser data missing for AKI/SKI path check.",
                        policy_value=True,
                        actual_value=False,
                    )
                )
            else:
                leaf_aki = parser_data.get("authority_key_identifier")
                issuer_ski = issuer_parser_data.get("subject_key_identifier")
                aki_match = bool(leaf_aki and issuer_ski and leaf_aki == issuer_ski)
                checks.append(
                    self._check(
                        "rfc5280_path_aki_ski_match",
                        aki_match,
                        "Leaf AKI matches issuer SKI."
                        if aki_match
                        else "Leaf AKI does not match issuer SKI (or one is missing).",
                        policy_value=True,
                        actual_value=aki_match,
                    )
                )
        else:
            checks.append(
                self._na(
                    "rfc5280_path_aki_ski_match",
                    "RFC 5280 AKI/SKI path check disabled by policy.",
                    policy_value=False,
                    actual_value=None,
                )
            )

        return checks

    # -------------------------------------------------------- crypto transition

    def _crypto_transition_checks(
        self, policy: dict[str, Any], parser_data: dict[str, Any]
    ) -> list[CheckResult]:
        cfg = policy["crypto_transition"]
        if not cfg["enabled"]:
            return [
                self._na(
                    "crypto_transition_validity_target",
                    "Crypto transition validity target check disabled by policy.",
                    policy_value=cfg["target_max_validity_days"],
                    actual_value=parser_data.get("validity_days"),
                ),
                self._na(
                    "crypto_transition_rsa_target",
                    "Crypto transition RSA target check disabled by policy.",
                    policy_value=cfg["target_min_rsa_bits"],
                    actual_value=parser_data.get("rsa_key_size"),
                ),
                self._na(
                    "crypto_transition_signature_hash",
                    "Crypto transition signature hash check disabled by policy.",
                    policy_value=sorted(cfg["approved_signature_algorithms"]),
                    actual_value=parser_data.get("signature_algorithm"),
                ),
            ]

        target_validity = cfg["target_max_validity_days"]
        validity_days = self._exact_validity_days(parser_data)
        is_rsa = self._key_algorithm(parser_data) == "rsa"
        rsa_bits = parser_data.get("rsa_key_size")
        if not isinstance(rsa_bits, int) and is_rsa:
            rsa_bits = self._key_size_bits(parser_data)
        target_rsa = cfg["target_min_rsa_bits"]
        signature_algorithm = str(parser_data.get("signature_algorithm", "")).lower()
        approved_hashes = {
            value.lower()
            for value in cfg["approved_signature_algorithms"]
            if value.strip()
        }

        checks = [
            self._check(
                "crypto_transition_validity_target",
                validity_days is not None and validity_days <= target_validity,
                (
                    f"Certificate validity is {validity_days:g} days "
                    f"(target <= {target_validity})."
                    if validity_days is not None
                    else "Certificate validity value missing for crypto transition check."
                ),
                policy_value=target_validity,
                actual_value=validity_days,
            )
        ]

        if is_rsa:
            checks.append(
                self._check(
                    "crypto_transition_rsa_target",
                    isinstance(rsa_bits, int) and rsa_bits >= target_rsa,
                    f"RSA key size is {rsa_bits} bits (target >= {target_rsa}).",
                    policy_value=target_rsa,
                    actual_value=rsa_bits,
                )
            )
        else:
            checks.append(
                self._na(
                    "crypto_transition_rsa_target",
                    f"Key algorithm is '{self._key_algorithm(parser_data)}'; "
                    "RSA transition target not applicable.",
                    policy_value=target_rsa,
                    actual_value=None,
                )
            )

        checks.append(
            self._check(
                "crypto_transition_signature_hash",
                signature_algorithm in approved_hashes,
                f"Signature algorithm is {signature_algorithm or 'missing'}.",
                policy_value=sorted(approved_hashes),
                actual_value=signature_algorithm or None,
            )
        )
        return checks

    # ---------------------------------------------------------------- issuance

    def _issuance_checks(
        self, policy: dict[str, Any], issuance_attestation: dict[str, Any] | None
    ) -> list[CheckResult]:
        issuance_cfg = policy["issuance"]
        if not issuance_cfg["require_hsm_attestation"]:
            return [
                self._na(
                    "issuance_hsm_attestation",
                    "Issuance HSM attestation checks disabled by policy.",
                    policy_value=False,
                    actual_value=None,
                ),
                self._na(
                    "issuance_fips_level",
                    "Issuance FIPS level checks disabled by policy.",
                    policy_value=issuance_cfg["min_fips_level"],
                    actual_value=None,
                ),
            ]

        if not isinstance(issuance_attestation, dict):
            return [
                self._check(
                    "issuance_hsm_attestation",
                    False,
                    "Issuance attestation is required but missing.",
                    policy_value=True,
                    actual_value=False,
                ),
                self._check(
                    "issuance_fips_level",
                    False,
                    "FIPS level attestation missing.",
                    policy_value=issuance_cfg["min_fips_level"],
                    actual_value=None,
                ),
            ]

        hsm_backed = bool(issuance_attestation.get("hsm_backed"))
        fips_level = issuance_attestation.get("fips_level")
        fips_ok = isinstance(fips_level, int) and fips_level >= issuance_cfg[
            "min_fips_level"
        ]

        return [
            self._check(
                "issuance_hsm_attestation",
                hsm_backed,
                "Issuance attestation confirms HSM-backed key operations."
                if hsm_backed
                else "Issuance attestation does not confirm HSM-backed key operations.",
                policy_value=True,
                actual_value=hsm_backed,
            ),
            self._check(
                "issuance_fips_level",
                fips_ok,
                f"Attested FIPS level is {fips_level} "
                f"(min {issuance_cfg['min_fips_level']}).",
                policy_value=issuance_cfg["min_fips_level"],
                actual_value=fips_level,
            ),
        ]

    # ----------------------------------------------------------------- domains

    def _internal_domain_checks(
        self, policy: dict[str, Any], parser_data: dict[str, Any]
    ) -> list[CheckResult]:
        domains_cfg = policy["domains"]
        san_dns = [d.lower() for d in parser_data["san_dns"]]
        if not domains_cfg["forbid_internal_names"]:
            return [
                self._na(
                    "internal_domain_check",
                    "Internal domain check disabled by policy "
                    "(domains.forbid_internal_names=false).",
                    policy_value=False,
                    actual_value=san_dns,
                )
            ]

        blocked_suffixes = tuple(s.lower() for s in domains_cfg["blocked_suffixes"])
        offending = [d for d in san_dns if blocked_suffixes and d.endswith(blocked_suffixes)]
        return [
            self._check(
                "internal_domain_check",
                not offending,
                (
                    "Blocked internal domains found: " + ", ".join(offending)
                    if offending
                    else "No blocked internal domains detected"
                ),
                policy_value=list(blocked_suffixes),
                actual_value=san_dns,
            )
        ]

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _exact_validity_days(parser_data: dict[str, Any]) -> float | None:
        """Return exact duration in days, with compatibility for older parser data."""
        seconds = parser_data.get("validity_seconds")
        if isinstance(seconds, (int, float)) and not isinstance(seconds, bool):
            return float(seconds) / 86_400
        days = parser_data.get("validity_days")
        if isinstance(days, (int, float)) and not isinstance(days, bool):
            return float(days)
        return None

    def _key_algorithm(self, parser_data: dict[str, Any]) -> str:
        """Resolve the key algorithm, tolerating pre-2.0 parser payloads.

        The parser now emits a normalised ``key_algorithm``, but external
        callers and stored reports may still carry only ``is_rsa``.
        """
        algorithm = parser_data.get("key_algorithm")
        if isinstance(algorithm, str) and algorithm.strip():
            return algorithm.strip().lower()
        if parser_data.get("is_rsa"):
            return "rsa"
        if parser_data.get("ec_curve"):
            return "ec"
        return "unknown"

    def _key_size_bits(self, parser_data: dict[str, Any]) -> Any:
        size = parser_data.get("key_size_bits")
        if isinstance(size, int):
            return size
        return parser_data.get("rsa_key_size")

    def _check(
        self,
        name: str,
        condition: bool,
        details: str,
        policy_value: Any = None,
        actual_value: Any = None,
    ) -> CheckResult:
        return self._result(
            name,
            "pass" if condition else "fail",
            details,
            policy_value,
            actual_value,
        )

    def _na(
        self,
        name: str,
        details: str,
        policy_value: Any = None,
        actual_value: Any = None,
    ) -> CheckResult:
        """Record a control policy did not enable.

        Emitting ``not_applicable`` rather than a synthetic ``pass`` is what
        keeps the evidence honest: the report states the control was defined
        but not assessed, instead of claiming it succeeded.
        """
        return self._result(name, "not_applicable", details, policy_value, actual_value)

    def _result(
        self,
        name: str,
        status: Status,
        details: str,
        policy_value: Any,
        actual_value: Any,
    ) -> CheckResult:
        meta = CHECK_METADATA.get(name, {})
        return CheckResult(
            name=name,
            status=status,
            details=details,
            rule_id=meta.get("rule_id"),
            category=meta.get("category"),
            severity=meta.get("severity"),
            standard_reference=meta.get("standard_reference"),
            policy_value=policy_value,
            actual_value=actual_value,
            rationale=meta.get("rationale"),
            recommendation=meta.get("recommendation"),
        )
