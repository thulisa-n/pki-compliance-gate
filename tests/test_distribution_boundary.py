"""Static guardrails for the public package and trusted publisher."""

import tomllib
from pathlib import Path


def test_public_distribution_only_discovers_core_namespace() -> None:
    with Path("pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)

    assert project["project"]["name"] == "pki-compliance-gate"
    # `neakam` is a public import shim. Enterprise packages stay out of this list.
    discovered = project["tool"]["setuptools"]["packages"]["find"]["include"]
    assert discovered == [
        "certguard",
        "certguard.*",
        "neakam",
        "neakam.*",
    ]
    assert "certguard_enterprise" not in discovered


def test_pypi_job_is_pinned_to_public_repository() -> None:
    workflow = Path(".github/workflows/publish.yml").read_text(encoding="utf-8")

    assert "github.repository == 'thulisa-n/pki-compliance-gate'" in workflow
