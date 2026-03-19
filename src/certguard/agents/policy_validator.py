from __future__ import annotations

from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult

CHECK_METADATA: dict[str, dict[str, str]] = {
    "validity_days": {
        "category": "VALIDITY",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 7.1.2.4",
        "rationale": "Long validity windows increase exposure when private keys are compromised.",
        "recommendation": "Reissue certificate with validity at or below policy threshold.",
    },
    "san_extension": {
        "category": "IDENTITY",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 7.1.4.2.1",
        "rationale": "Modern TLS clients rely on SAN for hostname validation.",
        "recommendation": "Issue certificate with SAN entries matching intended hostnames.",
    },
    "rsa_key_size": {
        "category": "CRYPTOGRAPHY",
        "severity": "critical",
        "standard_reference": "CA/B Forum BR 6.1.5",
        "rationale": "Weak RSA keys reduce cryptographic strength and trust assurance.",
        "recommendation": "Generate key pair with RSA 2048+ before issuance.",
    },
    "signature_algorithm": {
        "category": "CRYPTOGRAPHY",
        "severity": "critical",
        "standard_reference": "CA/B Forum BR 7.1.3",
        "rationale": "Deprecated hash algorithms can be vulnerable to collision attacks.",
        "recommendation": "Use SHA-256 or stronger signature algorithm.",
    },
    "internal_domain_check": {
        "category": "POLICY",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 7.1.4.2.1",
        "rationale": "Internal names are not valid for publicly trusted certificates.",
        "recommendation": "Replace internal SAN values with public DNS names.",
    },
}


class PolicyValidatorAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="policy_validator_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        policy = context["policy"]
        parser_data = context["parser_data"]
        checks: list[CheckResult] = []

        max_validity = policy["certificate"]["max_validity_days"]
        validity_days = parser_data["validity_days"]
        checks.append(
            self._check(
                "validity_days",
                validity_days <= max_validity,
                f"Certificate validity is {validity_days} days (max {max_validity})",
                policy_value=max_validity,
                actual_value=validity_days,
            )
        )

        require_san = policy["certificate"]["require_san"]
        san_dns = parser_data["san_dns"]
        checks.append(
            self._check(
                "san_extension",
                (not require_san) or bool(san_dns),
                "SAN extension present" if san_dns else "SAN extension missing",
                policy_value=require_san,
                actual_value=bool(san_dns),
            )
        )

        min_rsa_bits = policy["key"]["minimum_rsa_bits"]
        is_rsa = parser_data["is_rsa"]
        rsa_bits = parser_data["rsa_key_size"]
        rsa_ok = (not is_rsa) or (rsa_bits is not None and rsa_bits >= min_rsa_bits)
        checks.append(
            self._check(
                "rsa_key_size",
                rsa_ok,
                (
                    f"RSA key size is {rsa_bits} bits (min {min_rsa_bits})"
                    if is_rsa
                    else "Non-RSA key; RSA size check not applicable"
                ),
                policy_value=min_rsa_bits,
                actual_value=rsa_bits,
            )
        )

        forbidden_algorithms = {
            algo.lower() for algo in policy["signature"]["prohibited_algorithms"]
        }
        signature_algorithm = parser_data["signature_algorithm"].lower()
        checks.append(
            self._check(
                "signature_algorithm",
                signature_algorithm not in forbidden_algorithms,
                f"Signature algorithm is {signature_algorithm}",
                policy_value=sorted(forbidden_algorithms),
                actual_value=signature_algorithm,
            )
        )

        domain_checks = self._internal_domain_checks(policy, parser_data)
        checks.extend(domain_checks)

        success = all(check.status == "pass" for check in checks)
        return AgentResult(agent=self.name, success=success, checks=checks)

    def _internal_domain_checks(
        self, policy: dict[str, Any], parser_data: dict[str, Any]
    ) -> list[CheckResult]:
        domains_cfg = policy["domains"]
        if not domains_cfg["forbid_internal_names"]:
            return [
                self._check(
                    "internal_domain_check",
                    True,
                    "Internal domain check disabled by policy",
                    policy_value=False,
                    actual_value=False,
                )
            ]

        blocked_suffixes = tuple(s.lower() for s in domains_cfg["blocked_suffixes"])
        san_dns = [d.lower() for d in parser_data["san_dns"]]
        offending = [d for d in san_dns if d.endswith(blocked_suffixes)]
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

    def _check(
        self,
        name: str,
        condition: bool,
        details: str,
        policy_value: Any = None,
        actual_value: Any = None,
    ) -> CheckResult:
        meta = CHECK_METADATA.get(name, {})
        return CheckResult(
            name=name,
            status="pass" if condition else "fail",
            details=details,
            category=meta.get("category"),
            severity=meta.get("severity"),
            standard_reference=meta.get("standard_reference"),
            policy_value=policy_value,
            actual_value=actual_value,
            rationale=meta.get("rationale"),
            recommendation=meta.get("recommendation"),
        )
