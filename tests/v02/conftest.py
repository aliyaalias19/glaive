"""Shared fixtures for the v0.2 feature tests.

Imports of later-stage modules happen inside the fixtures, so each feature's
tests can run as soon as that feature exists.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from glaive.mcp_server.session import GlaiveSession

H = "a" * 64
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def ev(event_id: int, channel: str, data: dict, *, t: str = "2026-09-14T09:00:00+00:00",
       host: str = "WS1", rid: int | None = None, **extra) -> dict:
    """Build a normalized event dict as the adapters produce."""
    e = {"event_id": event_id, "time_created": t, "computer": host, "channel": channel,
         "provider": None, "raw_data": {k: str(v) for k, v in data.items()},
         "_record_id": rid, "_evidence_hash": H, "_derivation": "test",
         "_uid": f"u{event_id}-{rid}-{t}"}
    e.update(extra)
    return e


@pytest.fixture(scope="session")
def demo_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from glaive.demo.case import write_demo_case

    d = tmp_path_factory.mktemp("demo") / "evidence"
    write_demo_case(d)
    return d


@pytest.fixture
def demo_session(tmp_path: Path, demo_dir: Path) -> GlaiveSession:
    from glaive.ingestion.pipeline import ingest_path
    from glaive.mcp_server.session import GlaiveSession

    s = GlaiveSession(analysis_dir=tmp_path / "case", case_name="Demo")
    ingest_path(s, demo_dir)
    return s
