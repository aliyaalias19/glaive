"""Smoke tests. These should always pass; they verify the basic plumbing."""
from __future__ import annotations

import subprocess
import sys


def test_package_imports() -> None:
    import glaive

    assert glaive.__version__ == "0.2.1"


def test_cli_version_runs() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "glaive.cli", "version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "glaive 0.2.1" in result.stdout


def test_cli_investigate_missing_path_exits_2() -> None:
    """A missing evidence path is a usage error (exit code 2), not a crash."""
    result = subprocess.run(
        [sys.executable, "-m", "glaive.cli", "investigate", "fake/path"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "Evidence not found" in result.stdout
