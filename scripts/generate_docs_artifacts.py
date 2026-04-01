from __future__ import annotations

import argparse
import difflib
import subprocess
from pathlib import Path


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
        _render_document(redline_md_path, redline_dir / f"{current.stem}_redline.docx", redline_md_path)
        _render_document(redline_md_path, redline_dir / f"{current.stem}_redline.pdf", redline_md_path)

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


def _render_document(source_path: Path, output_path: Path, format_hint: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    input_format = _input_format(format_hint)
    cwd = Path.cwd()
    source_rel = source_path.relative_to(cwd)
    output_rel = output_path.relative_to(cwd)
    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{cwd}:/data",
        "pandoc/latex:latest",
        "--from",
        input_format,
        "--to",
        "pdf" if output_path.suffix == ".pdf" else "docx",
        "--output",
        f"/data/{output_rel.as_posix()}",
        f"/data/{source_rel.as_posix()}",
    ]
    subprocess.run(docker_cmd, check=True)  # nosec B603


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
