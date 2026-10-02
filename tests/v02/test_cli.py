"""The glaive command line, run as a real subprocess."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

ENV = {k: v for k, v in os.environ.items()
       if not k.endswith("_API_KEY") and k not in ("OLLAMA_MODEL", "GLAIVE_PROVIDERS",
                                                    "GLAIVE_BASE_URL")}


def _cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "glaive.cli", *args], capture_output=True,
                          text=True, cwd=cwd, env={**ENV, "PYTHONPATH": str(Path.cwd())},
                          timeout=300)


def test_demo_investigate_verify(tmp_path: Path) -> None:
    r = _cli("demo", "--out", "d", "--offline", cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    # running it again must replace the old demo, whose evidence copies are read-only
    r = _cli("demo", "--out", "d", "--offline", cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "Recall:" in r.stdout and "Ungrounded statements in the report: 0" in r.stdout
    case = tmp_path / "d" / "case"
    assert (case / "report.html").exists() and (case / "case.glaive").exists()

    r = _cli("investigate", "d/evidence", "--out", "c2", "--offline", cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "detections" in r.stdout

    assert _cli("verify", "c2", cwd=tmp_path).returncode == 0
    stored = next((tmp_path / "c2" / "evidence_store").glob("*.jsonl"))
    os.chmod(stored, stat.S_IRUSR | stat.S_IWUSR)
    stored.write_text("tampered", encoding="utf-8")
    r = _cli("verify", "c2", cwd=tmp_path)
    assert r.returncode == 1 and "CHANGED" in r.stdout

    assert _cli("report", "c2", cwd=tmp_path).returncode == 0
    assert "Default model" in _cli("models", cwd=tmp_path).stdout
