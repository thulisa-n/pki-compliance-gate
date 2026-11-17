"""The Compliance Gate CycloneDX command still works on cyclonedx-bom 8."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPLIANCE = ROOT / ".github" / "workflows" / "compliance.yml"

# Flags accepted by cyclonedx-py 8 `requirements`. The v8 break was limited to
# `environment` probing (`-E`/`-S` with no interpreter) and is not used here.
SBOM_ARGV = [
    "cyclonedx-py",
    "requirements",
    "requirements.txt",
    "--output-format",
    "JSON",
    "--output-reproducible",
]


def _runtime_dependency_names() -> set[str]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    block = text.split("dependencies = [", 1)[1].split("]", 1)[0]
    return {match.group(1).lower() for match in re.finditer(r'"([A-Za-z0-9_.-]+)', block)}


def test_compliance_workflow_uses_the_v8_requirements_command() -> None:
    text = COMPLIANCE.read_text(encoding="utf-8")
    assert "cyclonedx-py requirements requirements.txt \\" in text
    assert "--output-format JSON" in text
    assert "--output-reproducible" in text
    assert "--output-file reports/sbom.cdx.json" in text
    assert "cyclonedx-py environment" not in text
    assert "cyclonedx-py env " not in text


def test_requirements_sbom_is_cyclonedx_and_lists_runtime_dependencies(tmp_path: Path) -> None:
    output = tmp_path / "sbom.cdx.json"
    result = subprocess.run(
        [*SBOM_ARGV, "--output-file", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["bomFormat"] == "CycloneDX"
    spec_version = document["specVersion"]
    assert isinstance(spec_version, str) and spec_version
    components = document["components"]
    assert isinstance(components, list) and components
    names = {str(component.get("name", "")).lower() for component in components}
    missing = _runtime_dependency_names() - names
    assert not missing, sorted(missing)
