"""EVTX reading: Rust fast path, python-evtx fallback, identical output."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from glaive.ingestion.evtx_adapter import (
    _canon,
    _json_event_to_dict,
    _normalize_time_string,
    fast_backend_available,
    iter_evtx_events,
)

# Public attack samples: git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
SAMPLES = Path(os.environ.get("GLAIVE_EVTX_SAMPLES", Path.home() / "evtx-samples"))


def test_canonical_values() -> None:
    assert _canon("0x000000000000f4be") == "0xf4be"
    assert _canon("365ABB72-7ACC-5CC4-0000-0010B2470300") == "{365abb72-7acc-5cc4-0000-0010b2470300}"
    assert _canon("True") == "true"
    assert _canon("a\r\nb") == "a\nb"
    assert _canon("plain") == "plain"


def test_time_normalization() -> None:
    assert _normalize_time_string("2025-04-12T08:21:44.894831Z") == "2025-04-12T08:21:44.894831+00:00"
    assert _normalize_time_string("2025-04-12 08:21:44") == "2025-04-12T08:21:44+00:00"


def test_rust_json_shape() -> None:
    event = {
        "System": {"EventID": 1102, "EventRecordID": 77, "Channel": "Security",
                   "Computer": "DC1", "Provider": {"#attributes": {"Name": "Eventlog"}},
                   "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T00:00:00Z"}}},
        "UserData": {"LogFileCleared": {"SubjectUserName": "admin", "SubjectDomainName": "CORP"}},
    }
    d = _json_event_to_dict(event, 1)
    assert d["_record_id"] == 77  # Windows record id, not the reader's counter
    assert d["raw_data"]["SubjectUserName"] == "admin"
    assert d["channel"] == "Security" and d["event_id"] == 1102


def test_unnamed_data_and_booleans() -> None:
    event = {"System": {"EventID": {"#text": 104}, "Computer": "h", "Channel": "System",
                        "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T00:00:00Z"}}},
             "EventData": {"Data": {"#text": ["a", "b"]}, "Initiated": True}}
    d = _json_event_to_dict(event, None)
    assert d["raw_data"]["Data0"] == "a" and d["raw_data"]["Data1"] == "b"
    assert d["raw_data"]["Initiated"] == "true"


@pytest.mark.skipif(not (fast_backend_available() and SAMPLES.exists()),
                    reason="needs the 'evtx' package and GLAIVE_EVTX_SAMPLES")
@pytest.mark.integration
def test_backends_agree_on_real_samples() -> None:
    files = sorted(SAMPLES.rglob("*.evtx"))[:40]
    key_fields = ("Image", "CommandLine", "ProcessId", "TargetUserName", "LogonType",
                  "ScriptBlockText", "TargetObject")
    for f in files:
        a = list(iter_evtx_events(f, backend="python"))
        b = list(iter_evtx_events(f, backend="fast"))
        assert len(a) == len(b)
        for x, y in zip(a, b, strict=True):
            assert (x["event_id"], x["computer"], x["channel"], x["_record_id"]) == \
                   (y["event_id"], y["computer"], y["channel"], y["_record_id"])
            for k in key_fields:
                assert x["raw_data"].get(k) == y["raw_data"].get(k), (f, k)


def test_damaged_evtx_yields_no_events(tmp_path: Path) -> None:
    """A truncated EVTX (common on live-response collections) yields nothing,
    whichever reader is installed, instead of raising."""
    f = tmp_path / "Security.evtx"
    f.write_bytes(b"ElfFile\x00" + b"\x00" * 1024)
    assert list(iter_evtx_events(f)) == []
