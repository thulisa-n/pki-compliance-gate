from __future__ import annotations

import argparse
import difflib
import os
import subprocess
import sys
from pathlib import Path

PANDOC_IMAGE = os.getenv(
    "PANDOC_LATEX_IMAGE",
    "pandoc/latex@sha256:467bb9a70723627a34eb7003e46a1bb7c9344ea4580a46c4c978860784a6a754",
)

# Pandoc defaults to pdflatex, which aborts on any character outside its input
# encoding (emoji, arrows, smart quotes). xelatex and lualatex are Unicode-native
# and downgrade unknown glyphs to a warning, so they are tried first and pdflatex
# is kept only as a last-resort fallback.
PDF_ENGINES: tuple[str, ...] = tuple(
    engine.strip()
    for engine in os.getenv("PANDOC_PDF_ENGINES", "xelatex,lualatex,pdflatex").split(",")
    if engine.strip()
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate DOCX/PDF final docs and redline artifacts for md/adoc files."
    )
    parser.add_argument(
        "--base-ref",
        default="HEAD~1",
        help="Git revision used as redline baseline.",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/docs",
        help="Base output directory for generated docs.",
    )
    args = parser.parse_args()

    repo_root = Path.cwd()
    output_dir = repo_root / args.output_dir
    final_dir = output_dir / "final"
    redline_dir = output_dir / "redline"
    final_dir.mkdir(parents=True, exist_ok=True)
    redline_dir.mkdir(parents=True, exist_ok=True)

    tracked_docs = _git_lines(["ls-files", "*.md", "*.adoc"])
    changed_docs = _git_lines(
        ["diff", "--name-only", args.base_ref, "HEAD", "--", "*.md", "*.adoc"]
    )

    for rel_path in tracked_docs:
        source = repo_root / rel_path
        if not source.exists():
            continue
        _render_document(source, final_dir / f"{source.stem}.docx", source)
        _render_document(source, final_dir / f"{source.stem}.pdf", source)

    for rel_path in changed_docs:
        current = repo_root / rel_path
        if not current.exists():
            continue
        previous_text = _git_show_text(args.base_ref, rel_path)
        if previous_text is None:
            continue
        current_text = current.read_text(encoding="utf-8")
        redline_markdown = _redline_markdown(previous_text, current_text)
        redline_md_path = redline_dir / f"{current.stem}_redline.md"
        redline_md_path.write_text(redline_markdown, encoding="utf-8")
        _render_document(
            redline_md_path,
            redline_dir / f"{current.stem}_redline.docx",
            redline_md_path,
        )
        _render_document(
            redline_md_path,
            redline_dir / f"{current.stem}_redline.pdf",
            redline_md_path,
            best_effort=True,
        )

    summary = output_dir / "manifest.txt"
    summary.write_text(
        "\n".join(
            [
                "Generated documentation artifacts",
                f"Final docs: {final_dir}",
                f"Redlines: {redline_dir}",
                f"Base ref: {args.base_ref}",
                f"Tracked docs: {len(tracked_docs)}",
                f"Redlined docs: {len(changed_docs)}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


def _render_document(
    source_path: Path, output_path: Path, format_hint: Path, best_effort: bool = False
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    engines: tuple[str | None, ...] = (
        PDF_ENGINES if output_path.suffix == ".pdf" else (None,)
    )
    last_error: subprocess.CalledProcessError | None = None

    for engine in engines:
        command = _docker_command(source_path, output_path, format_hint, engine)
        try:
            subprocess.run(command, check=True)  # nosec B603
            return
        except subprocess.CalledProcessError as exc:
            last_error = exc
            if engine is not None:
                print(
                    f"WARNING: {output_path.name} failed with pdf engine "
                    f"'{engine}'; trying next engine.",
                    file=sys.stderr,
                )

    if not best_effort:
        raise last_error  # type: ignore[misc]
    print(
        f"WARNING: Failed to render {output_path.name} (continuing): {last_error}",
        file=sys.stderr,
    )


def _docker_command(
    source_path: Path, output_path: Path, format_hint: Path, engine: str | None
) -> list[str]:
    cwd = Path.cwd()
    source_rel = source_path.relative_to(cwd)
    output_rel = output_path.relative_to(cwd)
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{cwd}:/data",
        PANDOC_IMAGE,
        "--from",
        _input_format(format_hint),
        "--to",
        "pdf" if output_path.suffix == ".pdf" else "docx",
    ]
    if engine is not None:
        command.append(f"--pdf-engine={engine}")
    command += [
        "--output",
        f"/data/{output_rel.as_posix()}",
        f"/data/{source_rel.as_posix()}",
    ]
    return command


def _input_format(path: Path) -> str:
    if path.suffix.lower() == ".adoc":
        return "asciidoc"
    return "markdown"


def _redline_markdown(previous: str, current: str) -> str:
    lines = ["# Redline", ""]
    diff = difflib.ndiff(previous.splitlines(), current.splitlines())
    for item in diff:
        prefix = item[:2]
        text = item[2:]
        if prefix == "- ":
            lines.append(f"- ~~{text}~~")
        elif prefix == "+ ":
            lines.append(f"- **{text}**")
        elif prefix == "  ":
            lines.append(f"- {text}")
    return "\n".join(lines) + "\n"


def _git_lines(args: list[str]) -> list[str]:
    result = subprocess.run(  # nosec B603
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _git_show_text(base_ref: str, rel_path: str) -> str | None:
    result = subprocess.run(  # nosec B603
        ["git", "show", f"{base_ref}:{rel_path}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout


if __name__ == "__main__":
    raise SystemExit(main())
