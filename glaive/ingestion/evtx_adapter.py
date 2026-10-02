"""EVTX binary -> event dict adapter.

Bridges an EVTX reader and our parsers (which accept dicts of normalized
fields). Specific event-handling logic (which Data fields matter for
Defender vs. Security) stays in the parsers; this adapter just makes EVTX
consumable.

Two backends, identical output:
  - "evtx" (pip install evtx): Rust-based, roughly 1000x faster. Used
    automatically when installed.
  - python-evtx: pure Python fallback, always available.

Design decisions (DECISIONS.md E1-E4):
  E1 - Generator: yields one dict per event, no full-load
  E2 - One adapter per source format
  E3 - Path cleanup for Defender's quirky 'file:_C:\\...' prefixes done here
  E4 - Malformed records skipped, count tracked
"""
from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import Evtx.Evtx as evtx_lib
from lxml import etree

try:  # optional fast backend
    import evtx as _rust_evtx  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - depends on environment
    _rust_evtx = None

logger = logging.getLogger(__name__)


_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


@dataclass
class EvtxReadStats:
    """Stats from reading an EVTX file."""

    records_read: int = 0
    records_yielded: int = 0
    records_skipped_malformed: int = 0
    backend: str = ""


def fast_backend_available() -> bool:
    return _rust_evtx is not None


_HEX = re.compile(r"^0x[0-9a-fA-F]+$")
_GUID = re.compile(r"^\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?$")


def _canon(value: str) -> str:
    """Render typed values identically regardless of backend: the two EVTX
    readers format GUIDs and hex integers differently."""
    if "\r\n" in value:
        value = value.replace("\r\n", "\n")
    if value in ("True", "False"):
        return value.lower()
    if _HEX.match(value):
        return hex(int(value, 16))
    m = _GUID.match(value)
    if m:
        return "{" + m.group(1).lower() + "}"
    return value


def _canon_all(raw: dict[str, str]) -> dict[str, str]:
    return {k: _canon(v) for k, v in raw.items()}


def iter_evtx_events(
    path: Path,
    stats: EvtxReadStats | None = None,
    backend: str = "auto",
) -> Iterator[dict]:
    """Parse a binary EVTX file and yield event dicts.

    Each dict has the same shape our parsers expect:
        {
            "event_id": int,
            "time_created": str (ISO 8601 UTC),
            "computer": str,
            "channel": str | None,             # e.g. "Security"
            "provider": str | None,            # e.g. "Microsoft-Windows-Sysmon"
            "threat_name": str | None,         # only for Defender events
            "action": str | None,              # only for Defender events
            "file_path": str | None,           # only for Defender events
            "raw_data": {<all Data Name/value pairs, as strings>},
            "_record_id": int,                 # EVTX EventRecordID for traceability
        }

    backend: "auto" (fast if installed), "fast", or "python".
    If `stats` is provided, it's mutated in place with read counts.
    """
    if stats is None:
        stats = EvtxReadStats()

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"EVTX file not found: {path}")

    use_fast = backend == "fast" or (backend == "auto" and _rust_evtx is not None)
    if use_fast:
        if _rust_evtx is None:
            raise RuntimeError("Fast EVTX backend requested but 'evtx' is not installed.")
        try:
            parser = _rust_evtx.PyEvtxParser(str(path))
        except (OSError, RuntimeError) as e:
            if backend == "fast":
                raise
            # Damaged or truncated files are common in real incidents. The
            # Rust reader refuses some headers python-evtx can still read.
            logger.warning("Fast EVTX reader could not open %s (%s); using python-evtx",
                           path.name, e)
        else:
            stats.backend = "evtx-rs"
            yield from _iter_fast(parser, stats)
            return

    stats.backend = "python-evtx"
    with evtx_lib.Evtx(str(path)) as log:
        for record in log.records():
            stats.records_read += 1
            try:
                event_dict = _record_to_dict(record)
            except (etree.XMLSyntaxError, ValueError, AttributeError):
                # Malformed XML or unexpected structure - skip
                stats.records_skipped_malformed += 1
                continue

            if event_dict is None:
                stats.records_skipped_malformed += 1
                continue

            stats.records_yielded += 1
            yield event_dict


# ---- fast backend (Rust "evtx" package, JSON output) ---------------------------


def _text(v: Any) -> str:
    """Render a JSON value the way it appears as XML text."""
    if v is None:
        return ""
    if isinstance(v, dict):
        if "#text" in v:
            return _text(v["#text"])
        return ""
    if isinstance(v, list):
        return "\n".join(_text(x) for x in v)
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _flatten_userdata(obj: Any, out: dict[str, str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.startswith("#"):
                continue
            if isinstance(v, dict) and not ("#text" in v and len(v) <= 2):
                _flatten_userdata(v, out)
            else:
                t = _text(v).strip()
                if t:
                    out.setdefault(k, t)


def _iter_fast(parser: Any, stats: EvtxReadStats) -> Iterator[dict]:
    for rec in parser.records_json():
        stats.records_read += 1
        try:
            ev = json.loads(rec["data"])["Event"]
            event_dict = _json_event_to_dict(ev, rec.get("event_record_id"))
        except (KeyError, ValueError, TypeError):
            event_dict = None
        if event_dict is None:
            stats.records_skipped_malformed += 1
            continue
        stats.records_yielded += 1
        yield event_dict


def _json_event_to_dict(ev: dict, record_id: int | None) -> dict | None:
    system = ev.get("System") or {}
    eid = system.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text")
    if eid is None:
        return None
    tc = (system.get("TimeCreated") or {}).get("#attributes", {}).get("SystemTime")
    computer = system.get("Computer")
    if not tc or not computer:
        return None
    provider = (system.get("Provider") or {}).get("#attributes", {}).get("Name")

    raw_data: dict[str, str] = {}
    event_data = ev.get("EventData")
    if isinstance(event_data, dict):
        unnamed = 0
        for k, v in event_data.items():
            if k.startswith("#"):
                continue
            if k == "Data":  # unnamed <Data> element(s)
                items = v if isinstance(v, list) else [v]
                for item in items:
                    texts = item.get("#text") if isinstance(item, dict) else item
                    for t in texts if isinstance(texts, list) else [texts]:
                        raw_data[f"Data{unnamed}"] = _text(t)
                        unnamed += 1
            else:
                raw_data[k] = _text(v)
    user_data = ev.get("UserData")
    if isinstance(user_data, dict):
        _flatten_userdata(user_data, raw_data)

    return {
        "event_id": int(eid),
        "time_created": _normalize_time_string(str(tc)),
        "computer": str(computer),
        "channel": system.get("Channel"),
        "provider": provider,
        "threat_name": raw_data.get("Threat Name"),
        "action": raw_data.get("Action Name"),
        "file_path": _clean_defender_path(raw_data.get("Path")),
        "raw_data": _canon_all(raw_data),
        # The Rust reader's own record counter is NOT the Windows EventRecordID;
        # always take the ID stored in the event itself.
        "_record_id": _int_or_none(system.get("EventRecordID")),
    }


def _int_or_none(v: Any) -> int | None:
    try:
        return int(_text(v))
    except (TypeError, ValueError):
        return None


# ---- python-evtx backend (XML output) ------------------------------------------


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

    # Optional: channel + provider tell parsers which log the event came from
    chan_elem = root.find("e:System/e:Channel", _NS)
    channel = chan_elem.text if chan_elem is not None and chan_elem.text else None
    prov_elem = root.find("e:System/e:Provider", _NS)
    provider = prov_elem.get("Name") if prov_elem is not None else None

    # All <Data Name="X">value</Data> pairs in EventData. Unnamed <Data>
    # elements (used by some System/legacy events) become Data0, Data1, ...
    raw_data: dict[str, str] = {}
    unnamed = 0
    for data_elem in root.findall("e:EventData/e:Data", _NS):
        name = data_elem.get("Name")
        if name is None:
            name = f"Data{unnamed}"
            unnamed += 1
        raw_data[name] = data_elem.text or ""

    # Some events (e.g. 1102 "audit log cleared") use <UserData> instead of
    # <EventData>. Flatten its leaf elements into raw_data too.
    user_data = root.find("e:UserData", _NS)
    if user_data is not None:
        for elem in user_data.iter():
            if len(elem) == 0 and elem.text and elem.text.strip():
                raw_data.setdefault(etree.QName(elem).localname, elem.text.strip())

    # Defender-specific fields (None for non-Defender events)
    threat_name = raw_data.get("Threat Name")
    action = raw_data.get("Action Name")
    file_path = _clean_defender_path(raw_data.get("Path"))

    return {
        "event_id": event_id,
        "time_created": time_created,
        "computer": computer,
        "channel": channel,
        "provider": provider,
        "threat_name": threat_name,
        "action": action,
        "file_path": file_path,
        "raw_data": _canon_all(raw_data),
        "_record_id": record_id,
    }


def _normalize_time_string(ts: str) -> str:
    """Normalize EVTX timestamps to ISO 8601 with an explicit UTC offset.

    python-evtx yields '2025-04-12 08:21:44.894831+00:00'
    the Rust backend   '2025-04-12T08:21:44.894831Z'
    Both become        '2025-04-12T08:21:44.894831+00:00'.
    """
    s = ts.strip()
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return s
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()


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
