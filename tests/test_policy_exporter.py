"""The CP/CPS export must cover every control the engine can emit.

The exporter previously hand-wrote five parameters and ignored the rfc5280,
dcv, issuance, opa and crypto_transition sections, so the module whose stated
purpose was preventing documentation drift was itself the drift.
"""

from __future__ import annotations

from pathlib import Path

from certguard.agents.policy_validator import CHECK_METADATA
from certguard.policy_exporter import (
    SECTION_MAP,
    control_register_markdown,
    export_policy_to_markdown,
)

POLICY_FILE = Path("policies/cabf_policy.yaml")


def test_export_policy_to_markdown(tmp_path: Path) -> None:
    out_file = tmp_path / "CPS_SECTION_7.md"
    content = export_policy_to_markdown(POLICY_FILE, out_file)

    assert out_file.exists()
    assert "# Certificate Policy Specification (CP/CPS Section 7)" in content
    assert "CABF-BR-6.3.2" in content
    assert "Validity Period" in content
    assert "200 days" in content


def test_export_covers_every_enforced_control(tmp_path: Path) -> None:
    content = export_policy_to_markdown(POLICY_FILE, tmp_path / "out.md")

    missing = [name for name in CHECK_METADATA if f"`{name}`" not in content]
    assert not missing, f"controls missing from CP/CPS export: {missing}"


def test_export_covers_every_policy_section(tmp_path: Path) -> None:
    content = export_policy_to_markdown(POLICY_FILE, tmp_path / "out.md")

    for heading, _rows in SECTION_MAP:
        assert f"#### {heading}" in content


def test_export_documents_the_new_controls(tmp_path: Path) -> None:
    content = export_policy_to_markdown(POLICY_FILE, tmp_path / "out.md")

    assert "Reject expired certificates" in content
    assert "Permitted EC curves" in content
    assert "Minimum EC key size" in content


def test_export_explains_not_applicable(tmp_path: Path) -> None:
    """A reader must not mistake an unassessed control for a passing one."""
    content = export_policy_to_markdown(POLICY_FILE, tmp_path / "out.md")

    assert "not_applicable" in content
    assert "never counted as a pass" in content


def test_control_register_is_reusable_for_the_readme() -> None:
    register = control_register_markdown()

    assert register.startswith("| Control | Rule ID |")
    for name in CHECK_METADATA:
        assert f"`{name}`" in register
