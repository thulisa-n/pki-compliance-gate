from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_REPOSITORY = "thulisa-n/pki-compliance-gate"
ENTERPRISE_REPOSITORY = "thulisa-n/pki-compliance-gate-enterprise"
ENTERPRISE_ROOTS = (
    ".enterprise-repository",
    "docs/private",
    "requirements-enterprise.txt",
    "src/certguard_enterprise",
)

PUBLIC_PROFILES = frozenset(
    {
        "ci_lint_gate.yaml",
        "crypto_agility_pqc_readiness.yaml",
        "short_lived_90d.yaml",
    }
)
CURATED_PROFILES = frozenset(
    {
        "ev_guidelines.yaml",
        "smime_br.yaml",
        "root_program_baseline.yaml",
        "cpcps_controls.yaml",
    }
)


def _repository_kind() -> str:
    repository = os.getenv("GITHUB_REPOSITORY")
    if repository == PUBLIC_REPOSITORY:
        return "public"
    if repository == ENTERPRISE_REPOSITORY:
        return "enterprise"
    return "enterprise" if (REPO_ROOT / ".enterprise-repository").exists() else "public"


def test_commercial_layer_matches_repository_boundary() -> None:
    present = {
        path for path in ENTERPRISE_ROOTS if (REPO_ROOT / path).exists()
    }

    if _repository_kind() == "public":
        assert not present, f"Enterprise-only paths leaked into public core: {present}"
    else:
        assert present == set(ENTERPRISE_ROOTS), (
            f"Private repository is missing enterprise paths: "
            f"{set(ENTERPRISE_ROOTS) - present}"
        )


def test_public_dependencies_exclude_enterprise_frameworks() -> None:
    if _repository_kind() != "public":
        return

    dependency_files = (
        (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8"),
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"),
    )
    forbidden = {"fastapi", "uvicorn", "httpx", "pydantic"}
    leaked = {
        dependency
        for dependency in forbidden
        if any(dependency in content.lower() for content in dependency_files)
    }
    assert not leaked, f"Enterprise-only dependencies leaked into public core: {leaked}"


def test_public_policy_directory_holds_only_public_profiles() -> None:
    present = {
        path.name for path in (REPO_ROOT / "policies" / "profiles").glob("*.yaml")
    }
    assert present == set(PUBLIC_PROFILES)
    assert not (present & CURATED_PROFILES)


def test_public_core_does_not_import_the_enterprise_package() -> None:
    offenders = []
    public_python = [
        *(REPO_ROOT / "src" / "certguard").rglob("*.py"),
        *(REPO_ROOT / "tests").rglob("*.py"),
    ]
    for path in sorted(public_python):
        if path == Path(__file__):
            continue
        source = path.read_text(encoding="utf-8")
        if (
            "from certguard_enterprise" in source
            or "import certguard_enterprise" in source
        ):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders


def test_enterprise_console_script_is_private() -> None:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if _repository_kind() == "public":
        assert "certguard-ent" not in pyproject
        assert "certguard_enterprise" not in pyproject


def test_public_value_surfaces_stay_in_the_core() -> None:
    core = REPO_ROOT / "src" / "certguard"
    for module in ("sarif.py", "github_output.py", "readiness.py", "controls.py", "rego.py"):
        assert (core / module).is_file(), f"{module} must remain in the public core"
