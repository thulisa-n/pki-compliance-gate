"""`neakam doctor` is an offline self-test with stable exit codes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from certguard import __version__
from certguard.cli import main
from certguard.doctor import EXIT_CHECK_FAILED, EXIT_OK, EXIT_USAGE, run_doctor

ROOT = Path(__file__).resolve().parents[1]


def test_doctor_passes_offline(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    assert run_doctor([]) == EXIT_OK
    captured = capsys.readouterr()
    assert captured.out.startswith("Neakam doctor\n")
    assert "[ok] python:" in captured.out
    assert "[ok] package:" in captured.out
    assert "[ok] policies:" in captured.out
    assert "[ok] fixture:" in captured.out
    assert "BEGIN CERTIFICATE" not in captured.out
    assert "PRIVATE KEY" not in captured.out
    assert captured.err == ""


def test_doctor_json_reports_each_check(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_doctor(["--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "neakam"
    assert payload["command"] == "doctor"
    assert payload["ok"] is True
    assert payload["version"] == __version__
    assert [item["name"] for item in payload["checks"]] == [
        "python",
        "package",
        "policies",
        "fixture",
    ]
    assert all(item["ok"] is True for item in payload["checks"])


def test_doctor_reports_an_old_python(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("certguard.doctor.sys.version_info", (3, 10, 0, "final", 0))
    assert run_doctor(["--json"]) == EXIT_CHECK_FAILED
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    python_check = payload["checks"][0]
    assert python_check["name"] == "python"
    assert python_check["ok"] is False
    assert "3.10" in python_check["detail"]
    assert "Traceback" not in captured.err
    assert captured.err.strip() == "ERROR: doctor found a failed check"


def test_doctor_usage_error_is_exit_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_doctor(["--not-a-flag"]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert captured.out == ""


def test_doctor_help_is_exit_0(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_doctor(["--help"]) == EXIT_OK
    captured = capsys.readouterr()
    assert "neakam doctor" in captured.out
    assert captured.err == ""


def test_debug_shows_a_traceback_without_key_or_licence_material(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def explode() -> tuple[bool, str]:
        raise RuntimeError("-----BEGIN PRIVATE KEY-----\nsecret licence text")

    monkeypatch.setattr("certguard.doctor._check_fixture", explode)
    assert run_doctor(["--debug", "--json"]) == EXIT_CHECK_FAILED
    captured = capsys.readouterr()
    blob = captured.out + captured.err
    assert "Traceback" in captured.err
    assert "[redacted]" in captured.err
    assert "PRIVATE KEY" not in blob
    assert "licence" not in blob.lower()
    assert "BEGIN" not in blob
    payload = json.loads(captured.out)
    fixture = next(item for item in payload["checks"] if item["name"] == "fixture")
    assert fixture["ok"] is False
    assert fixture["detail"] == "check failed"


def test_cli_doctor_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["doctor", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "doctor"
    assert payload["ok"] is True


@pytest.mark.parametrize("alias", ["pki-gate", "certguard"])
def test_deprecated_alias_prints_one_line(
    alias: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", [f"/usr/local/bin/{alias}", "--version"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert captured.err == f"{alias} is deprecated; use neakam.\n"
    assert captured.out.strip() == f"neakam {__version__}"


def test_neakam_command_name_is_not_deprecated(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["/usr/local/bin/neakam", "--version"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.strip() == f"neakam {__version__}"


def test_help_uses_the_neakam_name(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["/usr/local/bin/neakam", "--help"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Neakam compliance gate" in captured.out
    assert "neakam doctor" in captured.out
    assert "--allow-network" in captured.out
    assert captured.err == ""


def test_module_entry_point_is_a_deprecated_alias() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    process = subprocess.run(
        [sys.executable, "-m", "certguard", "--version"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
        env=env,
    )
    assert process.returncode == 0
    assert process.stderr == "python -m certguard is deprecated; use neakam.\n"
    assert process.stdout.strip() == f"neakam {__version__}"


def test_distribution_name_stays_and_neakam_is_the_primary_script() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'name = "pki-compliance-gate"' in text
    assert 'neakam = "certguard.cli:main"' in text
    assert 'pki-gate = "certguard.cli:main"' in text
    assert 'certguard = "certguard.cli:main"' in text


def test_import_shim_reexports_the_version() -> None:
    import neakam

    assert neakam.__version__ == __version__
