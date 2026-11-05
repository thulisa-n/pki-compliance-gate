"""Run the neakam CLI the way a checkout does.

Prefer the installed console script. Fall back to ``python -m neakam`` so the
suite still runs before ``pip install``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def command() -> list[str]:
    found = shutil.which("neakam")
    if found:
        return [found]
    return [sys.executable, "-m", "neakam"]


def run(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    workdir = cwd or ROOT
    env = os.environ.copy()
    src = str(workdir / "src")
    previous = env.get("PYTHONPATH")
    env["PYTHONPATH"] = src if not previous else src + os.pathsep + previous
    return subprocess.run(
        [*command(), *args],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
