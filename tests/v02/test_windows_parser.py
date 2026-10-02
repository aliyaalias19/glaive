"""Windows Security, System, Sysmon and PowerShell event parsing."""
from __future__ import annotations

from pathlib import Path

from glaive.evidence.store import EvidenceStore
from glaive.graph.wrapper import EvidenceGraph
from glaive.ingestion.windows import (
    WindowsEventParser,
    classify_channel,
    is_internal_ip,
    split_registry_path,
)
from tests.v02.conftest import SYSMON, ev


def _parse(tmp_path: Path, events: list[dict]):
    r = WindowsEventParser(EvidenceStore(tmp_path / "s")).parse(events)
    g = EvidenceGraph()
    for n in r.nodes:
        g.add_node(n)
    for e in r.edges:
        g.add_edge(e)
    return r, g


def test_classify_channel() -> None:
    assert classify_channel({"channel": SYSMON}) == "sysmon"
    assert classify_channel({"channel": "Security"}) == "security"
    assert classify_channel({"channel": "Microsoft-Windows-Windows Defender/Operational"}) == "defender"
    assert classify_channel({"channel": "Microsoft-Windows-PowerShell/Operational"}) == "powershell"


def test_sysmon_and_4688_merge_into_one_confirmed_process(tmp_path: Path) -> None:
    t = "2026-09-14T09:13:02.100+00:00"
    events = [
        ev(1, SYSMON, {"ProcessId": 6644, "Image": "C:\\Windows\\powershell.exe",
                       "CommandLine": "powershell -enc AAA", "ParentProcessId": 5120,
                       "ParentImage": "C:\\Office\\WINWORD.EXE", "UtcTime": "2026-09-14 09:13:02.100",
                       "User": "CORP\\alice"}, t=t, rid=1),
        ev(4688, "Security", {"NewProcessId": "0x19f4", "NewProcessName": "C:\\Windows\\powershell.exe",
                              "CommandLine": "powershell -enc AAA", "ProcessId": "0x1400",
                              "ParentProcessName": "C:\\Office\\WINWORD.EXE"},
           t="2026-09-14T09:13:02.103+00:00", rid=2),
    ]
    r, g = _parse(tmp_path, events)
    procs = {n.name: n for n in g.find_nodes("Process")}
    assert set(procs) >= {"powershell.exe", "WINWORD.EXE"}
    ps = procs["powershell.exe"]
    assert sorted(ps.observed_by) == ["evtx_4688", "sysmon_1"]
    spawned = list(g.all_edges("Spawned"))
    assert len(spawned) == 1 and spawned[0].confidence == "confirmed"
    roles = {role for role, _ in r.event_entities[events[0]["_uid"]]}
    assert {"host", "parent", "process", "user"} <= roles


def test_pid_resolution_picks_process_alive_at_the_time(tmp_path: Path) -> None:
    events = [
        ev(1, SYSMON, {"ProcessId": 100, "Image": "C:\\old.exe", "UtcTime": "2026-09-14 08:00:00.000"},
           t="2026-09-14T08:00:00+00:00", rid=1),
        ev(1, SYSMON, {"ProcessId": 100, "Image": "C:\\new.exe", "UtcTime": "2026-09-14 09:00:00.000"},
           t="2026-09-14T09:00:00+00:00", rid=2),
        ev(3, SYSMON, {"ProcessId": 100, "Image": "C:\\new.exe", "DestinationIp": "8.8.8.8",
                       "DestinationPort": 53, "Protocol": "udp", "Initiated": "true",
                       "UtcTime": "2026-09-14 09:05:00.000"}, t="2026-09-14T09:05:00+00:00", rid=3),
    ]
    _, g = _parse(tmp_path, events)
    conn = next(g.all_edges("Connected"))
    assert g.get_node(conn.source_key).name == "new.exe"
    ep = g.get_node(conn.target_key)
    assert (ep.remote_addr, ep.remote_port, ep.is_internal, conn.direction) == (
        "8.8.8.8", 53, False, "outbound")


def test_logons_and_null_sid(tmp_path: Path) -> None:
    events = [
        ev(4625, "Security", {"TargetUserSid": "S-1-0-0", "TargetUserName": "bob",
                              "TargetDomainName": "CORP", "LogonType": 3, "IpAddress": "10.0.0.9",
                              "SubStatus": "0xc000006a"}, rid=1),
        ev(4624, "Security", {"TargetUserSid": "S-1-5-21-1-2-3-500", "TargetUserName": "administrator",
                              "TargetDomainName": "CORP", "LogonType": 10, "IpAddress": "10.0.0.9"},
           t="2026-09-14T09:01:00+00:00", rid=2),
    ]
    _, g = _parse(tmp_path, events)
    logons = list(g.all_edges("Logon"))
    assert {lg.success for lg in logons} == {True, False}
    failed = next(lg for lg in logons if not lg.success)
    assert failed.failure_reason == "0xc000006a"
    assert g.get_node(failed.source_key).sid.startswith("UNRESOLVED:CORP\\bob")


def test_service_task_registry_file_dns_script(tmp_path: Path) -> None:
    events = [
        ev(7045, "System", {"ServiceName": "Evil", "ImagePath": "C:\\Temp\\e.exe",
                            "StartType": "auto start", "AccountName": "LocalSystem"}, rid=1),
        ev(4698, "Security", {"TaskName": "\\Updater",
                              "TaskContent": "<Task><Actions><Exec><Command>C:\\x.exe</Command>"
                                             "<Arguments>-q</Arguments></Exec></Actions></Task>"}, rid=2),
        ev(13, SYSMON, {"ProcessId": 5, "Image": "C:\\x.exe", "EventType": "SetValue",
                        "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x",
                        "Details": "C:\\x.exe"}, rid=3),
        ev(11, SYSMON, {"ProcessId": 5, "Image": "C:\\x.exe", "TargetFilename": "C:\\drop.dll"},
           rid=4),
        ev(22, SYSMON, {"ProcessId": 5, "Image": "C:\\x.exe", "QueryName": "evil.example"}, rid=5),
        ev(4104, "Microsoft-Windows-PowerShell/Operational",
           {"ScriptBlockId": "{1}", "ScriptBlockText": "Write-Host hi"}, rid=6, _process_id=5),
    ]
    r, g = _parse(tmp_path, events)
    assert r.events_malformed == 0 and r.events_used == 6
    counts = g.type_counts()
    for t in ("Service", "ScheduledTask", "RegistryKey", "File", "NetworkEndpoint", "ScriptBlock"):
        assert counts.get(t), t
    assert {e.mechanism for e in g.all_edges("Persisted")} == {"service", "scheduled_task"}
    reg = next(g.find_nodes("RegistryKey"))
    assert (reg.hive_name, reg.value_name) == ("HKLM", "x")
    assert any(True for _ in g.all_edges("Ran"))


def test_events_without_provenance_are_ignored(tmp_path: Path) -> None:
    e = ev(1, SYSMON, {"ProcessId": 1, "Image": "C:\\a.exe"})
    e["_evidence_hash"] = None
    r, _ = _parse(tmp_path, [e])
    assert r.nodes == [] and r.events_ignored == 1


def test_malformed_events_are_counted_not_fatal(tmp_path: Path) -> None:
    r, _ = _parse(tmp_path, [ev(1, SYSMON, {"Image": "C:\\a.exe"})])  # no ProcessId
    assert r.events_malformed == 1


def test_helpers() -> None:
    assert split_registry_path("\\REGISTRY\\MACHINE\\SOFTWARE\\Run\\v") == (
        "HKLM", "SOFTWARE\\Run", "v")
    assert split_registry_path("\\REGISTRY\\USER\\S-1-5-21\\Run\\v")[0] == "HKU"
    assert is_internal_ip("10.1.2.3") and is_internal_ip("172.20.0.1")
    assert not is_internal_ip("8.8.8.8")
