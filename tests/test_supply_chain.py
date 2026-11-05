"""CI installs from the hash lock and does not float third-party Actions."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION = ROOT / "action.yml"

_PIP_INSTALL = re.compile(r"^.*pip install .*$", re.M)
_USES = re.compile(r"uses:\s*['\"]?([^'\"\s#]+)")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _workflow_text() -> list[tuple[Path, str]]:
    files = sorted(WORKFLOWS.glob("*.yml"))
    files.append(ACTION)
    return [(path, path.read_text(encoding="utf-8")) for path in files]


def test_requirement_files_are_hash_pinned() -> None:
    for name in ("requirements.txt", "requirements-dev.txt"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "pip-compile" in text
        assert "--generate-hashes" in text
        assert "--hash=sha256:" in text
    dev = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "--extra=dev" in dev


def test_pip_installs_require_hashes_or_are_local() -> None:
    """Third-party installs use the lock. Local project and wheel installs use --no-deps."""
    for path, text in _workflow_text():
        for line in _PIP_INSTALL.findall(text):
            stripped = line.strip()
            if "requirements-enterprise.txt" in stripped:
                continue
            assert "--require-hashes" in stripped or "--no-deps" in stripped, (
                f"{path.name}: {stripped}"
            )


def test_third_party_actions_are_pinned_to_commits() -> None:
    for path, text in _workflow_text():
        for uses in _USES.findall(text):
            if uses.startswith("./"):
                continue
            owner_repo, _, ref = uses.partition("@")
            assert ref, f"{path.name} has no ref for {uses}"
            assert _SHA.fullmatch(ref), f"{path.name} {owner_repo} is not pinned to a SHA ({ref})"


def test_workflows_default_to_contents_read() -> None:
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        assert "contents: read" in text, path.name


def test_security_scans_fail_on_medium() -> None:
    text = (WORKFLOWS / "security-scans.yml").read_text(encoding="utf-8")
    assert "--severity-level medium" in text
    assert "scripts/pip_audit_gate.py" in text
    assert "requirements-dev.txt" in text


def test_workflows_do_not_echo_secrets() -> None:
    echo_secret = re.compile(r"echo\b.*secrets\.", re.I)
    for path, text in _workflow_text():
        assert echo_secret.search(text) is None, path.name
