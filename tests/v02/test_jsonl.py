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


def test_nxlog_flat_record_as_in_otrf_datasets() -> None:
    # Shape of OTRF Security-Datasets (NXLog -> Logstash): fields at the top
    # level, the real host in "Hostname", "host" is the log collector.
    ev = normalize_json_event({
        "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "SourceName": "Microsoft-Windows-Sysmon", "host": "wec.internal.cloudapp.net",
        "Hostname": "WORKSTATION5.theshire.local", "EventTime": "2020-09-21 18:58:57",
        "@timestamp": "2020-09-21T22:58:59.043Z", "UtcTime": "2020-09-21 22:58:57.121",
        "RecordNumber": 4242, "ExecutionProcessID": 3172, "port": 64545,
        "Image": "C:\\windows\\system32\\whoami.exe", "CommandLine": "whoami /user",
        "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ProcessId": "8840", "tags": ["mordorDataset"]})
    assert ev is not None
    assert ev["computer"] == "WORKSTATION5.theshire.local"
    assert ev["time_created"] == "2020-09-21T22:58:57.121000+00:00"  # UtcTime, not EventTime
    assert ev["raw_data"]["CommandLine"] == "whoami /user"
    assert "port" not in ev["raw_data"] and "Hostname" not in ev["raw_data"]
    assert ev["_record_id"] == 4242 and ev["provider"] == "Microsoft-Windows-Sysmon"


def test_nxlog_record_without_utctime_uses_timestamp() -> None:
    ev = normalize_json_event({"EventID": 4624, "Channel": "Security",
                               "Hostname": "DC1", "@timestamp": "2020-09-21T22:59:14.904Z",
                               "TargetUserName": "pgustavo", "LogonType": 3})
    assert ev is not None and ev["time_created"].startswith("2020-09-21T22:59:14")
    assert ev["raw_data"]["LogonType"] == "3"


def test_winlogbeat_record() -> None:
    ev = normalize_json_event({
        "@timestamp": "2026-03-01T10:00:00.000Z",
        "winlog": {"event_id": 4688, "computer_name": "WS01", "channel": "Security",
                   "provider_name": "Microsoft-Windows-Security-Auditing", "record_id": 77,
                   "event_data": {"NewProcessName": "C:\\Windows\\System32\\cmd.exe"}}})
    assert ev is not None and ev["computer"] == "WS01" and ev["event_id"] == 4688
    assert ev["raw_data"]["NewProcessName"].endswith("cmd.exe") and ev["_record_id"] == 77
