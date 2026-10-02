"""Integration: the public EVTX-ATTACK-SAMPLES set, end to end.

git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
set GLAIVE_EVTX_SAMPLES to that folder, then: pytest -m integration
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from glaive.agents import RuleInvestigator
from glaive.eval import score_session
from glaive.ingestion.pipeline import ingest_path
from glaive.mcp_server.session import GlaiveSession

SAMPLES = Path(os.environ.get("GLAIVE_EVTX_SAMPLES", Path.home() / "evtx-samples"))


@pytest.mark.skipif(not SAMPLES.exists(), reason="set GLAIVE_EVTX_SAMPLES to EVTX-ATTACK-SAMPLES")
@pytest.mark.integration
def test_real_attack_samples_end_to_end(tmp_path: Path) -> None:
    """All 278 real EVTX files: nothing crashes, nothing is fabricated."""
    s = GlaiveSession(analysis_dir=tmp_path / "case")
    summary = ingest_path(s, SAMPLES)
    assert summary.events_total > 30_000
    assert all(f.status != "error" for f in summary.files)
    assert summary.alerts > 100
    for n in s.graph.find_nodes():
        assert s.store.has(n.evidence_hash), n.canonical_key()  # no fabricated provenance
    RuleInvestigator(s).run()
    assert len(s.report.findings) > 20
    assert score_session(s, []).ungrounded_in_report == 0
