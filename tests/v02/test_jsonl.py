"""JSON / JSON-Lines event exports (EvtxECmd, Chainsaw, evtx_dump, GLAIVE)."""
from __future__ import annotations

import json
from pathlib import Path

from glaive.ingestion.jsonl import iter_json_events, normalize_json_event


def test_jsonl_flat_and_nested(tmp_path: Path) -> None:
    p = tmp_path / "x.jsonl"
    p.write_text("\n".join([
        json.dumps({"EventID": 4688, "TimeCreated": "2026-01-01T00:00:00Z", "Computer": "h",
                    "Channel": "Security", "EventData": {"NewProcessId": "0x10"}}),
        "not json",
        json.dumps({"Event": {"System": {"EventID": 1, "Computer": "h", "Channel": "x",
                                         "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T00:00:00Z"}}},
                              "EventData": {"Image": "C:\\a.exe"}}}),
        "",
    ]), encoding="utf-8")
    stats: dict[str, int] = {}
    events = list(iter_json_events(p, stats))
    assert [e["event_id"] for e in events] == [4688, 1]
    assert stats["records_skipped_malformed"] == 1
    assert events[0]["raw_data"]["NewProcessId"] == "0x10"


def test_json_array(tmp_path: Path) -> None:
    p = tmp_path / "x.json"
    p.write_text(json.dumps([{"event_id": 1, "time_created": "2026-01-01T00:00:00Z",
                              "computer": "h", "raw_data": {"a": 1}}]), encoding="utf-8")
    assert list(iter_json_events(p))[0]["raw_data"] == {"a": "1"}


def test_normalize_rejects_incomplete() -> None:
    assert normalize_json_event({"EventID": 1}) is None
    assert normalize_json_event([1, 2]) is None


def test_bad_record_in_json_array_is_skipped(tmp_path: Path) -> None:
    p = tmp_path / "x.json"
    good = {"event_id": 1, "time_created": "2026-01-01T00:00:00Z", "computer": "h"}
    p.write_text(json.dumps([{**good, "event_id": "abc"}, good]), encoding="utf-8")
    stats: dict[str, int] = {}
    assert [e["event_id"] for e in iter_json_events(p, stats)] == [1]
    assert stats["records_skipped_malformed"] == 1
