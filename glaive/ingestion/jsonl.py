"""JSON / JSON-Lines event reader.

Accepts the event shape GLAIVE uses internally (one object per line):

    {"event_id": 4688, "time_created": "2025-04-12T08:21:44Z",
     "computer": "WS01", "channel": "Security", "raw_data": {...}}

and the common export shapes produced by tools such as EvtxECmd, Chainsaw
or `evtx_dump -o jsonl` (Event.System / Event.EventData nesting, or flat
EventID/TimeCreated/Computer/Channel keys). This makes the synthetic demo
case, test fixtures and exports from other tools all ingestible.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from glaive.ingestion.evtx_adapter import (
    _canon_all,
    _clean_defender_path,
    _json_event_to_dict,
    _normalize_time_string,
)


def _from_flat(obj: dict[str, Any]) -> dict | None:
    eid = obj.get("event_id", obj.get("EventID", obj.get("EventId")))
    ts = obj.get("time_created", obj.get("TimeCreated", obj.get("@timestamp")))
    if isinstance(ts, dict):
        ts = ts.get("SystemTime")
    computer = obj.get("computer", obj.get("Computer", obj.get("host")))
    if eid is None or not ts or not computer:
        return None
    raw = obj.get("raw_data", obj.get("EventData", obj.get("Payload"))) or {}
    if not isinstance(raw, dict):
        raw = {"Payload": str(raw)}
    raw = _canon_all({k: "" if v is None else str(v) for k, v in raw.items()})
    return {
        "event_id": int(eid),
        "time_created": _normalize_time_string(str(ts)),
        "computer": str(computer),
        "channel": obj.get("channel", obj.get("Channel")),
        "provider": obj.get("provider", obj.get("Provider")),
        "threat_name": obj.get("threat_name") or raw.get("Threat Name"),
        "action": obj.get("action") or raw.get("Action Name"),
        "file_path": obj.get("file_path") or _clean_defender_path(raw.get("Path")),
        "raw_data": raw,
        "_record_id": obj.get("_record_id", obj.get("EventRecordId", obj.get("EventRecordID"))),
        "_process_id": obj.get("_process_id"),
    }


def normalize_json_event(obj: Any) -> dict | None:
    """Convert one JSON object (any supported shape) to a GLAIVE event dict."""
    if not isinstance(obj, dict):
        return None
    if "Event" in obj and isinstance(obj["Event"], dict):
        ev = obj["Event"]
        rec = (ev.get("System") or {}).get("EventRecordID")
        return _json_event_to_dict(ev, rec)
    return _from_flat(obj)


def iter_json_events(path: Path, stats: dict[str, int] | None = None) -> Iterator[dict]:
    """Yield normalized events from a .json (array) or .jsonl file."""
    stats = stats if stats is not None else {}
    stats.setdefault("records_read", 0)
    stats.setdefault("records_skipped_malformed", 0)
    path = Path(path)
    with open(path, encoding="utf-8-sig") as f:
        head = f.read(1)
        f.seek(0)
        if head == "[":
            items: Any = json.load(f)
            lines = items if isinstance(items, list) else []
            for obj in lines:
                stats["records_read"] += 1
                try:
                    ev = normalize_json_event(obj)
                except (ValueError, TypeError):  # e.g. "EventID": "abc"
                    ev = None
                if ev is None:
                    stats["records_skipped_malformed"] += 1
                    continue
                yield ev
            return
        for line in f:
            line = line.strip()
            if not line:
                continue
            stats["records_read"] += 1
            try:
                ev = normalize_json_event(json.loads(line))
            except (json.JSONDecodeError, ValueError, TypeError):
                ev = None
            if ev is None:
                stats["records_skipped_malformed"] += 1
                continue
            yield ev
