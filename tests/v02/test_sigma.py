"""Sigma engine semantics and the bundled rule pack."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from glaive.detection.sigma import (
    BUILTIN_RULES_DIR,
    SigmaEngine,
    UnsupportedRule,
    compile_rule,
    load_rules,
)
from tests.v02.conftest import SYSMON, ev


def rule(detection: str, logsource: str = "category: process_creation\n  product: windows") -> object:
    return compile_rule(yaml.safe_load(f"""
title: t
id: x
logsource:
  {logsource}
detection:
{detection}
level: high
"""))


def proc(cmd: str = "", image: str = "C:\\Windows\\System32\\cmd.exe", **more) -> dict:
    return ev(1, SYSMON, {"Image": image, "CommandLine": cmd, "ProcessId": 1, **more})


def hit(r: object, e: dict) -> bool:
    return bool(SigmaEngine([r]).match(e))


@pytest.mark.parametrize("det,cmd,expected", [
    ("  s:\n    CommandLine|contains: 'vssadmin'\n  condition: s", "x vssadmin y", True),
    ("  s:\n    CommandLine|contains: 'VSSADMIN'\n  condition: s", "vssadmin", True),
    ("  s:\n    CommandLine|startswith: 'cmd'\n  condition: s", "cmd /c", True),
    ("  s:\n    CommandLine|endswith: '.ps1'\n  condition: s", "run a.ps1", True),
    ("  s:\n    CommandLine|contains|all:\n      - a\n      - b\n  condition: s", "a only", False),
    ("  s:\n    CommandLine|contains|all:\n      - a\n      - b\n  condition: s", "a and b", True),
    ("  s:\n    CommandLine: 'cmd*/c'\n  condition: s", "cmd.exe /c", True),
    ("  s:\n    CommandLine|re: '^c.d '\n  condition: s", "cmd x", True),
    ("  s:\n    CommandLine|windash|contains: ' -enc '\n  condition: s", "ps /enc X", True),
    ("  s:\n    CommandLine|contains: '\\'\n  condition: s", "C:\\x", True),
    ("  s:\n    CommandLine|contains: '\\'\n  condition: s", "no slash", False),
    ("  s:\n    Missing: null\n  condition: s", "x", True),
    ("  s:\n    CommandLine|exists: true\n  condition: s", "x", True),
    ("  s:\n    - x1\n    - zz\n  condition: s", "has zz in it", True),
])
def test_modifiers(det: str, cmd: str, expected: bool) -> None:
    assert hit(rule(det), proc(cmd)) is expected


def test_conditions() -> None:
    det = """  a:
    CommandLine|contains: one
  b:
    CommandLine|contains: two
  filter:
    CommandLine|contains: skip
  condition: (a or b) and not filter"""
    r = rule(det)
    assert hit(r, proc("one"))
    assert hit(r, proc("two"))
    assert not hit(r, proc("one skip"))
    r2 = rule("  sel_a:\n    CommandLine|contains: a\n  sel_b:\n    CommandLine|contains: b\n"
              "  condition: all of sel_*")
    assert hit(r2, proc("ab")) and not hit(r2, proc("a"))
    r3 = rule("  x:\n    CommandLine|contains: q\n  condition: 1 of them")
    assert hit(r3, proc("q"))


def test_cidr_and_logsource() -> None:
    r = rule("  s:\n    DestinationIp|cidr: '10.0.0.0/8'\n  condition: s",
             logsource="category: network_connection\n  product: windows")
    net = ev(3, SYSMON, {"DestinationIp": "10.2.3.4"})
    assert hit(r, net)
    assert not hit(r, ev(3, SYSMON, {"DestinationIp": "8.8.8.8"}))
    assert not hit(r, ev(1, SYSMON, {"DestinationIp": "10.2.3.4"}))  # wrong category


def test_security_4688_aliases_to_sysmon_names() -> None:
    r = rule("  s:\n    Image|endswith: '\\powershell.exe'\n    ParentImage|endswith: '\\winword.exe'\n"
             "  condition: s")
    e = ev(4688, "Security", {"NewProcessName": "C:\\x\\powershell.exe",
                              "ParentProcessName": "C:\\o\\WINWORD.EXE", "NewProcessId": "0x10",
                              "ProcessId": "0x20"})
    assert hit(r, e)


@pytest.mark.parametrize("bad", [
    "  s:\n    CommandLine: x\n  condition: s | count() > 5",
    "  s:\n    CommandLine|base64offset|contains: x\n  condition: s",
    "  s:\n    CommandLine: x\n  condition: missing_name",
])
def test_unsupported_features_are_refused(bad: str) -> None:
    with pytest.raises(UnsupportedRule):
        rule(bad)


def test_builtin_pack_compiles_and_has_metadata() -> None:
    rules, report = load_rules()
    assert report.skipped == []
    assert len(rules) >= 25
    for r in rules:
        assert r.level in ("informational", "low", "medium", "high", "critical")
        assert r.description
    assert all(r.mitre_techniques for r in rules)


def test_loader_reports_bad_files(tmp_path: Path) -> None:
    (tmp_path / "bad.yml").write_text("title: x\ndetection: [unclosed", encoding="utf-8")
    (tmp_path / "linux.yml").write_text(
        "title: x\nlogsource:\n  product: linux\ndetection:\n  s:\n    a: b\n  condition: s\n",
        encoding="utf-8")
    rules, report = load_rules([tmp_path], include_builtin=False)
    assert rules == [] and len(report.skipped) == 2


def test_rule_files_are_valid_yaml() -> None:
    for f in BUILTIN_RULES_DIR.glob("*.yml"):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        assert {"title", "id", "logsource", "detection", "level"} <= set(doc), f.name


def test_engine_prefilter_gives_the_same_matches_as_checking_every_rule(demo_dir: Path) -> None:
    from glaive.detection.sigma import event_view
    from glaive.ingestion.jsonl import iter_json_events
    from glaive.ingestion.windows import classify_channel

    rules, _ = load_rules()
    engine = SigmaEngine(rules)
    events = [e for f in sorted(demo_dir.glob("*.jsonl")) for e in iter_json_events(f)]
    assert len(events) > 100
    for e in events:
        view, fam, eid = event_view(e), classify_channel(e), e.get("event_id") or 0
        brute = [r.id for r in rules if r.matches(fam, eid, view)]
        assert [r.id for r in engine.match(e)] == brute
    assert len(engine._candidates) < len(events)  # worked out once per (family, event id)
