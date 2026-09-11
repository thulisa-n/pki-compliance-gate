from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "generate_docs_artifacts.py"


def _load_docs_artifacts():
    spec = importlib.util.spec_from_file_location("generate_docs_artifacts", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


docs_artifacts = _load_docs_artifacts()


def test_pdf_rendering_prefers_unicode_capable_engine() -> None:
    # pdflatex aborts on non-ASCII content, so it must never be the first choice.
    assert docs_artifacts.PDF_ENGINES[0] in {"xelatex", "lualatex"}


def test_docker_command_selects_pdf_engine(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "doc.md"
    source.write_text("# Title\n", encoding="utf-8")

    pdf_command = docs_artifacts._docker_command(
        source, tmp_path / "out" / "doc.pdf", source, "xelatex"
    )
    docx_command = docs_artifacts._docker_command(
        source, tmp_path / "out" / "doc.docx", source, None
    )

    assert "--pdf-engine=xelatex" in pdf_command
    assert not any(arg.startswith("--pdf-engine") for arg in docx_command)


def test_render_document_falls_back_to_next_engine(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "doc.md"
    source.write_text("# Title\n", encoding="utf-8")
    attempted: list[str] = []

    def fake_run(command: list[str], check: bool = False):
        engine = next(
            arg.split("=", 1)[1] for arg in command if arg.startswith("--pdf-engine=")
        )
        attempted.append(engine)
        if len(attempted) == 1:
            raise subprocess.CalledProcessError(43, command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(docs_artifacts.subprocess, "run", fake_run)
    docs_artifacts._render_document(source, tmp_path / "doc.pdf", source)

    assert attempted == list(docs_artifacts.PDF_ENGINES[:2])


def test_render_document_raises_when_all_engines_fail(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "doc.md"
    source.write_text("# Title\n", encoding="utf-8")

    def always_fail(command: list[str], check: bool = False):
        raise subprocess.CalledProcessError(43, command)

    monkeypatch.setattr(docs_artifacts.subprocess, "run", always_fail)

    try:
        docs_artifacts._render_document(source, tmp_path / "doc.pdf", source)
    except subprocess.CalledProcessError:
        pass
    else:  # pragma: no cover - guard against silent regression
        raise AssertionError("Strict rendering must surface engine failures.")

    # Best-effort rendering stays non-fatal for redlines.
    docs_artifacts._render_document(
        source, tmp_path / "doc.pdf", source, best_effort=True
    )
