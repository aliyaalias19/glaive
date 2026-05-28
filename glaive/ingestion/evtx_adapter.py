"""EVTX binary -> event dict adapter.

Bridges python-evtx (which yields XML strings) and our parsers (which accept
dicts of normalized fields). Specific event-handling logic (which Data fields
matter for Defender vs. Security) stays in the parsers; this adapter just
makes EVTX consumable.

Design decisions (DECISIONS.md E1-E4):
  E1 — Generator: yields one dict per event, no full-load
  E2 — One adapter per source format
  E3 — Path cleanup for Defender's quirky 'file:_C:\\...' prefixes done here
  E4 — Malformed records skipped, count tracked
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import Evtx.Evtx as evtx_lib
from lxml import etree


logger = logging.getLogger(__name__)


_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


@dataclass
class EvtxReadStats:
    """Stats from reading an EVTX file."""

    records_read: int = 0
    records_yielded: int = 0
    records_skipped_malformed: int = 0


def iter_evtx_events(
    path: Path,
    stats: EvtxReadStats | None = None,
) -> Iterator[dict]:
    """Parse a binary EVTX file and yield event dicts.

    Each dict has the same shape our parsers expect:
        {
            "event_id": int,
            "time_created": str (ISO 8601 UTC),
            "computer": str,
            "threat_name": str | None,         # only for Defender events
            "action": str | None,              # only for Defender events
            "file_path": str | None,           # only for Defender events
            "raw_data": {<all Data Name/value pairs>},
            "_record_id": int,                 # EVTX EventRecordID for traceability
        }

    For non-Defender event types, the threat_name/action/file_path fields will
    be None or missing; the parser is responsible for ignoring those.

    If `stats` is provided, it's mutated in place with read counts.
    """
    if stats is None:
        stats = EvtxReadStats()

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"EVTX file not found: {path}")

    with evtx_lib.Evtx(str(path)) as log:
        for record in log.records():
            stats.records_read += 1
            try:
                event_dict = _record_to_dict(record)
            except (etree.XMLSyntaxError, ValueError, AttributeError):
                # Malformed XML or unexpected structure — skip
                stats.records_skipped_malformed += 1
                continue

            if event_dict is None:
                stats.records_skipped_malformed += 1
                continue

            stats.records_yielded += 1
            yield event_dict


def _record_to_dict(record) -> dict | None:
    """Convert one EVTX record to our dict format.

    Returns None for records that lack required fields (event_id, time, computer).
    """
    root = etree.fromstring(record.xml())

    # Required: event_id
    eid_elem = root.find("e:System/e:EventID", _NS)
    if eid_elem is None or eid_elem.text is None:
        return None
    event_id = int(eid_elem.text)

    # Required: time_created
    tc_elem = root.find("e:System/e:TimeCreated", _NS)
    if tc_elem is None:
        return None
    time_created = tc_elem.get("SystemTime")
    if time_created is None:
        return None
    time_created = _normalize_time_string(time_created)

    # Required: computer
    comp_elem = root.find("e:System/e:Computer", _NS)
    if comp_elem is None or comp_elem.text is None:
        return None
    computer = comp_elem.text

    # Optional: EventRecordID (useful for traceability)
    rec_id_elem = root.find("e:System/e:EventRecordID", _NS)
    record_id = int(rec_id_elem.text) if rec_id_elem is not None and rec_id_elem.text else None

    # All <Data Name="X">value</Data> pairs in EventData
    raw_data: dict[str, str] = {}
    for data_elem in root.findall("e:EventData/e:Data", _NS):
        name = data_elem.get("Name")
        if name is None:
            continue
        raw_data[name] = data_elem.text or ""

    # Defender-specific fields (None for non-Defender events)
    threat_name = raw_data.get("Threat Name")
    action = raw_data.get("Action Name")
    file_path = _clean_defender_path(raw_data.get("Path"))

    return {
        "event_id": event_id,
        "time_created": time_created,
        "computer": computer,
        "threat_name": threat_name,
        "action": action,
        "file_path": file_path,
        "raw_data": raw_data,
        "_record_id": record_id,
    }


def _normalize_time_string(ts: str) -> str:
    """Normalize python-evtx's space-separated time format to ISO 8601 'T' separator.

    python-evtx yields:    '2025-04-12 08:21:44.894831+00:00'
    We want (ISO 8601):    '2025-04-12T08:21:44.894831+00:00'

    The 'T' form is what datetime.fromisoformat handles directly on all Python
    versions; the space form works on 3.11+ but we normalize to be safe.
    """
    if " " in ts and "T" not in ts:
        return ts.replace(" ", "T", 1)
    return ts


def _clean_defender_path(raw_path: str | None) -> str | None:
    """Normalize Defender's quirky path format.

    Real examples we saw:
        'file:_C:\\Users\\USER\\Downloads\\foo.zip'
        'file:_C:\\Users\\USER\\Downloads\\foo.zip; webfile:_...;...'

    We extract the first 'file:_' or 'webfile:_' prefixed entry and strip
    the prefix. If neither prefix is present, return the raw string.
    """
    if not raw_path:
        return None

    # Split semicolon-delimited multi-source paths; take the first one
    first_entry = raw_path.split(";")[0].strip()

    # Strip 'file:_' or 'webfile:_' prefix
    for prefix in ("file:_", "webfile:_"):
        if first_entry.startswith(prefix):
            return first_entry[len(prefix):]

    return first_entry
