"""Smoke tests. These should always pass; they verify the basic plumbing."""
from __future__ import annotations

import subprocess
import sys


def test_package_imports() -> None:
    import glaive

    assert glaive.__version__ == "0.1.0"


def test_cli_version_runs() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "glaive.cli", "version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "glaive 0.1.0" in result.stdout


def test_cli_investigate_is_stubbed() -> None:
    """Until Week 2, investigate should explicitly say 'not yet implemented'."""
    result = subprocess.run(
        [sys.executable, "-m", "glaive.cli", "investigate", "fake/path"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "not yet implemented" in result.stdout
