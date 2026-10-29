"""Prove import-linter rejects a forbidden dependency in core."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def test_import_contract_detects_core_dependency_on_evidence(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    copied = tmp_path / "project"
    shutil.copytree(project / "src", copied / "src")
    shutil.copy(project / ".importlinter", copied / ".importlinter")
    (copied / "src/cyberwall/evidence/store.py").write_text("", encoding="utf-8")
    core_init = copied / "src/cyberwall/core/__init__.py"
    core_init.write_text(
        core_init.read_text(encoding="utf-8") + "\nfrom cyberwall.evidence import store\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [shutil.which("lint-imports") or "lint-imports", "--no-cache"],
        cwd=copied,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(copied / "src")},
    )
    assert result.returncode != 0
    assert "core has no inward dependencies" in result.stdout + result.stderr
