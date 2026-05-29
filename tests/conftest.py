"""Shared pytest fixtures for GLAIVE tests.

Session-scoped fixtures defined here are available to every test under
tests/, but live for the entire pytest session — so the expensive parse
of the real Defender.evtx happens ONCE, not per-test-file.
"""
from __future__ import annotations

from pathlib import Path

import pytest


REAL_EVTX = Path(__file__).resolve().parent.parent / "test_evidence" / "Defender.evtx"


@pytest.fixture(scope="session")
def real_defender_events() -> tuple[list[dict], "EvtxReadStats"]:
    """Parse test_evidence/Defender.evtx ONCE per pytest session.

    Integration tests that need the parsed events should depend on this
    fixture instead of calling iter_evtx_events themselves (or calling
    do_ingest_artifact with the file path, which re-parses internally).

    Returns (events, stats) — the stats object tracks records_read,
    records_yielded, records_skipped_malformed for assertions.
    Skips the test if the file isn't present.
    """
    if not REAL_EVTX.exists():
        pytest.skip("Real Defender.evtx not present (test_evidence/ is gitignored).")
    from glaive.ingestion.evtx_adapter import EvtxReadStats, iter_evtx_events
    stats = EvtxReadStats()
    events = list(iter_evtx_events(REAL_EVTX, stats))
    return events, stats


@pytest.fixture(scope="session")
def real_evtx_path() -> Path:
    """The path to test_evidence/Defender.evtx, or skip if absent.

    Useful for tests that need the path itself (e.g. testing the orchestrator's
    source_path handling) without re-parsing — they can pass it to a function
    that takes a Path argument.
    """
    if not REAL_EVTX.exists():
        pytest.skip("Real Defender.evtx not present.")
    return REAL_EVTX



@pytest.fixture
def populated_session(tmp_path, real_defender_events):
    """A fresh GlaiveSession with the real Defender events already ingested.

    Each test gets a NEW session (function-scoped) — state isolation
    preserved — but the expensive parse from real_defender_events
    (session-scoped) is reused. Result: every test gets a populated graph
    in milliseconds, not minutes.
    """
    from glaive.ingestion.defender import DefenderEvtxParser
    from glaive.mcp_server.session import GlaiveSession

    session = GlaiveSession(analysis_dir=tmp_path)
    events, _stats = real_defender_events
    parser = DefenderEvtxParser(session.store)
    session.orchestrator.run(parser, source_path=REAL_EVTX, parse_input=events)
    return session
