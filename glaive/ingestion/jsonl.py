"""JSON / JSON-Lines event reader.

Accepts the event shape GLAIVE uses internally (one object per line):

    {"event_id": 4688, "time_created": "2025-04-12T08:21:44Z",
     "computer": "WS01", "channel": "Security", "raw_data": {...}}

and the common export shapes produced by tools such as EvtxECmd, Chainsaw
or `evtx_dump -o jsonl` (Event.System / Event.EventData nesting, or flat
EventID/TimeCreated/Computer/Channel keys). This makes the synthetic demo
case, test fixtures and exports from other tools all ingestible.

Also log-shipper exports:
  - NXLog / Logstash (used by OTRF Security-Datasets): every field at the top
    level, the host in "Hostname" (not "host", which is the collector).
  - Winlogbeat / Elastic: {"winlog": {"event_id", "computer_name",
    "channel", "event_data": {...}}, "@timestamp": ...}.
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

# NXLog / Logstash bookkeeping fields: everything else in a flat NXLog record
# is event data.
_SHIPPER_FIELDS = frozenset({
    "EventID", "EventTime", "EventReceivedTime", "EventType", "SourceModuleName",
    "SourceModuleType", "SourceName", "ProviderGuid", "Hostname", "host", "port", "tags",
    "Channel", "Keywords", "SeverityValue", "Severity", "Opcode", "OpcodeValue", "RecordNumber",
    "ExecutionProcessID", "ThreadID", "Task", "Version", "Category", "@version", "@timestamp",
    "ERROR_EVT_UNRESOLVED", "AccountType", "AccountName", "Domain", "UserID",
})


def _from_nxlog(obj: dict[str, Any]) -> dict | None:
    """Flat NXLog / Logstash record (OTRF Security-Datasets)."""
    computer = obj.get("Hostname")
    # Sysmon's UtcTime is the event time; @timestamp is when Logstash received it.
    ts = obj.get("UtcTime") or obj.get("@timestamp") or obj.get("EventTime")
    eid = obj.get("EventID")
    if eid is None or not ts or not computer:
        return None
    raw = {k: "" if v is None else (v if isinstance(v, str) else json.dumps(v)
                                    if isinstance(v, (dict, list)) else str(v))
           for k, v in obj.items() if k not in _SHIPPER_FIELDS}
    raw = _canon_all(raw)
    return {
        "event_id": int(eid),
        "time_created": _normalize_time_string(str(ts)),
        "computer": str(computer),
        "channel": obj.get("Channel"),
        "provider": obj.get("SourceName"),
        "threat_name": raw.get("Threat Name"),
        "action": raw.get("Action Name"),
        "file_path": _clean_defender_path(raw.get("Path")),
        "raw_data": raw,
        "_record_id": obj.get("RecordNumber"),
        "_process_id": obj.get("ExecutionProcessID"),
    }


def _from_winlogbeat(obj: dict[str, Any]) -> dict | None:
    wl = obj["winlog"]
    eid = wl.get("event_id")
    ts = obj.get("@timestamp")
    computer = wl.get("computer_name")
    if eid is None or not ts or not computer:
        return None
    data = wl.get("event_data") or {}
    raw = _canon_all({k: "" if v is None else str(v) for k, v in data.items()})
    proc = wl.get("process") or {}
    return {
        "event_id": int(eid),
        "time_created": _normalize_time_string(str(ts)),
        "computer": str(computer),
        "channel": wl.get("channel"),
        "provider": wl.get("provider_name"),
        "threat_name": raw.get("Threat Name"),
        "action": raw.get("Action Name"),
        "file_path": _clean_defender_path(raw.get("Path")),
        "raw_data": raw,
        "_record_id": wl.get("record_id"),
        "_process_id": proc.get("pid") if isinstance(proc, dict) else None,
    }


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
    if isinstance(obj.get("winlog"), dict):
        return _from_winlogbeat(obj)
    if "Hostname" in obj and "EventID" in obj and not any(
            k in obj for k in ("EventData", "raw_data", "Payload")):
        return _from_nxlog(obj)
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
