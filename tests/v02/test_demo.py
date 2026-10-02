"""The Operation Invoice demo case generator."""
from __future__ import annotations

import json
from pathlib import Path

from glaive.demo.case import ANSWER_KEY, build_events, write_demo_case
from glaive.evidence.store import EvidenceStore
from glaive.ingestion.jsonl import iter_json_events
from glaive.ingestion.windows import WindowsEventParser


def test_same_seed_gives_identical_evidence() -> None:
    assert build_events(seed=7) == build_events(seed=7)


def test_writes_logs_and_answer_key(tmp_path: Path) -> None:
    paths = write_demo_case(tmp_path / "evidence")
    assert paths and all(p.suffix == ".jsonl" for p in paths)
    key = json.loads((tmp_path / "evidence_ANSWER_KEY.json").read_text(encoding="utf-8"))
    assert [k["id"] for k in key] == [gt.id for gt in ANSWER_KEY]


def test_every_event_is_readable_and_parseable(tmp_path: Path) -> None:
    events = []
    for p in write_demo_case(tmp_path / "evidence"):
        stats: dict[str, int] = {}
        events += list(iter_json_events(p, stats))
        assert stats["records_skipped_malformed"] == 0, p.name
    for e in events:
        e["_evidence_hash"] = "a" * 64
    r = WindowsEventParser(EvidenceStore(tmp_path / "store")).parse(events)
    assert r.events_malformed == 0
    assert r.events_used > 50
