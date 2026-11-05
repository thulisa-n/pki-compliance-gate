#!/usr/bin/env bash
# Regenerate the hash-pinned requirement files from pyproject.toml.
#
# CI installs these files with `pip install --require-hashes`. Run this with
# Python 3.11 after changing project.dependencies or the dev extra, then commit
# both files. Dependabot replays the pip-compile command recorded in the header.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if ! command -v pip-compile >/dev/null 2>&1; then
  echo "pip-compile is not on PATH. Install the dev extra (pip-tools) first." >&2
  exit 1
fi

pip-compile --allow-unsafe --generate-hashes --output-file=requirements.txt --strip-extras pyproject.toml
pip-compile --allow-unsafe --extra=dev --generate-hashes --output-file=requirements-dev.txt --strip-extras pyproject.toml
