"""Emit OPA/Rego from the YAML policy so the gate cannot drift.

A hand-written ``policies/rego/validity.rego`` with ``input.validity_days <= 200``
was a fourth copy of the truth: the YAML could move to the 2027 100-day phase
and the OPA gate would still pass 200-day certificates. Evaluation and
``export-rego`` both call ``render_validity_rego`` so the limit always comes
from ``certificate.max_validity_days``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from certguard.policy import load_policy


def max_validity_days_from_policy(policy: dict[str, Any]) -> int:
    return int(policy["certificate"]["max_validity_days"])


def render_validity_rego(policy: dict[str, Any]) -> str:
    """Return a Rego package whose allow rule uses the YAML validity limit."""
    max_days = max_validity_days_from_policy(policy)
    return (
        "package pki.compliance\n"
        "\n"
        f"# Generated from certificate.max_validity_days = {max_days}.\n"
        "# Do not edit. Change the YAML profile and re-export.\n"
        "# Evaluated only when opa.enabled=true.\n"
        "\n"
        "default allow := false\n"
        "\n"
        "allow if {\n"
        f"    input.validity_days <= {max_days}\n"
        "}\n"
    )


def export_policy_to_rego(policy_path: str | Path, output_path: str | Path) -> str:
    """Load a policy YAML file and write the generated Rego next to it."""
    policy = load_policy(Path(policy_path))
    rendered = render_validity_rego(policy)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(rendered, encoding="utf-8")
    return rendered
