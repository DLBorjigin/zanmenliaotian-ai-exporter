#!/usr/bin/env python3
"""Small Skill entrypoint that delegates to the local exporter package."""

from __future__ import annotations

import os
from pathlib import Path
import runpy
import sys


def _project_src() -> Path:
    configured = os.environ.get("WECHAT_AI_EXPORTER_HOME")
    if configured:
        return Path(configured).expanduser().resolve() / "src"
    skill_dir = Path(__file__).resolve().parents[1]
    bundled = skill_dir / "runtime" / "src"
    if bundled.is_dir():
        return bundled
    candidate = skill_dir.parents[1] / "src"
    if candidate.is_dir():
        return candidate
    raise SystemExit(
        "The exporter runtime is missing from this Skill package. Reinstall the "
        "complete release, or set WECHAT_AI_EXPORTER_HOME to its installation directory."
    )


if __name__ == "__main__":
    sys.path.insert(0, str(_project_src()))
    runpy.run_module("wechat_ai_exporter.cli", run_name="__main__")
