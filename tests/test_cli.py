"""CLI smoke tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _run(*args: str, root: Path) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "cli", "--root", str(root), *args]
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def test_cli_init_and_status(tmp_path: Path):
    r = _run("init", root=tmp_path)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "aegis_local.duckdb").is_file()
    assert (tmp_path / ".aegis_operator_token").is_file()

    r2 = _run("temperature", "set", "--value", "3.0", root=tmp_path)
    assert r2.returncode == 0, r2.stderr

    r3 = _run("status", root=tmp_path)
    assert r3.returncode == 0
    assert "3.0" in r3.stdout or "3" in r3.stdout
