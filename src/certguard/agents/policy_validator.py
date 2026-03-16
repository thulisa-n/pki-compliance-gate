from __future__ import annotations

from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult


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
            )
        )

        require_san = policy["certificate"]["require_san"]
        san_dns = parser_data["san_dns"]
        checks.append(
            self._check(
                "san_extension",
                (not require_san) or bool(san_dns),
                "SAN extension present" if san_dns else "SAN extension missing",
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
                CheckResult(
                    name="internal_domain_check",
                    status="pass",
                    details="Internal domain check disabled by policy",
                )
            ]

        blocked_suffixes = tuple(s.lower() for s in domains_cfg["blocked_suffixes"])
        san_dns = [d.lower() for d in parser_data["san_dns"]]
        offending = [d for d in san_dns if d.endswith(blocked_suffixes)]
        return [
            CheckResult(
                name="internal_domain_check",
                status="fail" if offending else "pass",
                details=(
                    "Blocked internal domains found: " + ", ".join(offending)
                    if offending
                    else "No blocked internal domains detected"
                ),
            )
        ]

    def _check(self, name: str, condition: bool, details: str) -> CheckResult:
        return CheckResult(name=name, status="pass" if condition else "fail", details=details)
