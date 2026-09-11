from __future__ import annotations

import os
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_REPOSITORY = "thulisa-n/pki-compliance-gate"
ENTERPRISE_REPOSITORY = "thulisa-n/pki-compliance-gate-enterprise"
ENTERPRISE_PATHS = (
    "requirements-enterprise.txt",
    "src/certguard_enterprise/api/server.py",
    "src/certguard_enterprise/doc_publisher.py",
    "tests/test_api_server.py",
    "tests/test_doc_publisher.py",
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
        path for path in ENTERPRISE_PATHS if (REPO_ROOT / path).exists()
    }

    if _repository_kind() == "public":
        assert not present, f"Enterprise-only paths leaked into public core: {present}"
    else:
        assert present == set(ENTERPRISE_PATHS), (
            f"Private repository is missing enterprise paths: "
            f"{set(ENTERPRISE_PATHS) - present}"
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
