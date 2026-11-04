"""`--mode` help keeps decision modes distinct from render-only helpers."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from certguard.cli import DERIVED_HELPER_MODES, FIRST_CLASS_MODES, parse_args

CLI_SOURCE = Path("src/certguard/cli.py").read_text(encoding="utf-8")


def test_mode_groups_are_disjoint_and_dispatched() -> None:
    assert FIRST_CLASS_MODES
    assert DERIVED_HELPER_MODES
    assert set(FIRST_CLASS_MODES).isdisjoint(DERIVED_HELPER_MODES)
    for mode in (*FIRST_CLASS_MODES, *DERIVED_HELPER_MODES):
        assert f'args.mode == "{mode}"' in CLI_SOURCE


def test_mode_help_separates_first_class_modes_from_derived_helpers() -> None:
    env = os.environ.copy()
    env["COLUMNS"] = "400"
    process = subprocess.run(
        [sys.executable, "src/main.py", "--help"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert process.returncode == 0
    collapsed = " ".join(process.stdout.split())

    first_at = collapsed.index("First-class modes:")
    derived_at = collapsed.index("Derived helpers:")
    assert first_at < derived_at
    first_section = collapsed[first_at:derived_at]
    # `--cert` also appears in the usage line, above this help text.
    derived_section = collapsed[derived_at:].split("--cert", 1)[0]

    for mode in FIRST_CLASS_MODES:
        assert mode in first_section
        assert mode not in derived_section
    for mode in DERIVED_HELPER_MODES:
        assert mode in derived_section
        assert mode not in first_section

    usage = collapsed.split("First-class modes:", 1)[0]
    assert "{" + ",".join(FIRST_CLASS_MODES) + "}" in usage
    assert "{" + ",".join(DERIVED_HELPER_MODES) + "}" in usage
    assert "|{" in usage


def test_grouped_modes_are_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    for mode in (*FIRST_CLASS_MODES, *DERIVED_HELPER_MODES):
        monkeypatch.setattr(sys, "argv", ["pki-gate", "--mode", mode])
        assert parse_args().mode == mode


def test_readme_lists_the_same_mode_groups() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    first, derived = readme.split("### First-class modes", 1)[1].split("### Derived helpers", 1)
    derived = derived.split("## Repository structure", 1)[0]
    for mode in FIRST_CLASS_MODES:
        assert f"`{mode}`" in first
        assert f"`{mode}`" not in derived
    for mode in DERIVED_HELPER_MODES:
        assert f"`{mode}`" in derived
        assert f"`{mode}`" not in first


def test_unknown_mode_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["pki-gate", "--mode", "not-a-mode"])
    with pytest.raises(SystemExit) as exc:
        parse_args()
    assert exc.value.code == 2
