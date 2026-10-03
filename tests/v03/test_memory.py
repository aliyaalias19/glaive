"""Past-case memory: opt-in, local, indicators matched across cases."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from glaive.agents import RuleInvestigator
from glaive.demo.case import C2
from glaive.ingestion.pipeline import ingest_path
from glaive.mcp_server.session import GlaiveSession
from glaive.memory import Memory, indicators, memory_path, open_memory


def _case(demo_dir: Path, root: Path, name: str) -> GlaiveSession:
    s = GlaiveSession(analysis_dir=root / name, case_name=name)
    ingest_path(s, demo_dir)
    RuleInvestigator(s).run()
    s.save()
    return s


def test_indicators_worth_matching() -> None:
    text = (f"powershell.exe downloaded http://{C2}/a.ps1 from 10.20.4.17 and wrote "
            "C:\\Users\\Public\\svchost32.exe and C:\\Windows\\System32\\cmd.exe; sha256 "
            + "ab" * 32 + " domain update-check.cdn-msft.com")
    found = indicators(text)
    assert f"ip:{C2}" in found and "ip:10.20.4.17" not in found
    assert any(i.startswith("sha256:") for i in found)
    assert any("svchost32.exe" in i for i in found)
    assert not any("system32" in i for i in found)
    assert "domain:update-check.cdn-msft.com" in found


def test_memory_is_opt_in_and_can_be_switched_off(tmp_path: Path) -> None:
    assert open_memory() is None  # nothing remembered yet
    assert memory_path({"GLAIVE_MEMORY": "off"}) is None
    assert memory_path({"GLAIVE_HOME": str(tmp_path)}) == tmp_path / "memory.sqlite"


def test_remember_search_overlap_forget(demo_dir: Path, tmp_path: Path) -> None:
    a = _case(demo_dir, tmp_path, "Operation A")
    with Memory(tmp_path / "m.sqlite") as mem:
        n = mem.remember(a)
        assert n == len(a.report.findings) > 5
        assert mem.remember(a) == n  # re-remembering replaces, never duplicates
        assert mem.cases()[0] == {"case_name": "Operation A", "findings": n,
                                  "remembered_at": mem.cases()[0]["remembered_at"]}
        hits = mem.search("shadow copies vssadmin")
        assert hits and hits[0].case_name == "Operation A" and "vssadmin" in hits[0].claim
        assert mem.search("vssadmin", exclude_case="Operation A") == []

        b = _case(demo_dir, tmp_path, "Operation B")
        over = mem.overlaps(b)
        assert any(o["indicator"] == f"ip:{C2}" and o["past_case"] == "Operation A"
                   for o in over)
        assert mem.overlaps(a) == []  # a case does not overlap with itself
        assert mem.forget("Operation A") == n and mem.search("vssadmin") == []


def test_rejected_findings_are_not_remembered(demo_dir: Path, tmp_path: Path) -> None:
    a = _case(demo_dir, tmp_path, "Op")
    pending = a.report.pending()[0]
    a.report.review(pending.finding_id, False, "lead", "admin activity")
    with Memory(tmp_path / "m.sqlite") as mem:
        assert mem.remember(a) == len(a.report.findings) - 1


def test_recall_tool_appears_only_with_memory(demo_dir: Path, tmp_path: Path) -> None:
    from glaive.agents.toolbox import AgentToolbox
    from glaive.llm import ToolCall

    b = _case(demo_dir, tmp_path, "Operation B")
    assert "recall_past_cases" not in [s.name for s in AgentToolbox(b).specs()]
    mem = open_memory(create=True)
    assert mem is not None
    with mem:
        mem.remember(_case(demo_dir, tmp_path, "Operation A"))
    tb = AgentToolbox(b)
    assert "recall_past_cases" in [s.name for s in tb.specs()]
    out = tb.execute(ToolCall("1", "recall_past_cases", {"query": "credential dumping"}))
    payload = json.loads("\n".join(out.splitlines()[1:-1]))
    assert payload["returned"] and all(r["case_name"] == "Operation A"
                                       for r in payload["past_findings"])
    assert "OTHER cases" in payload["note"]


def test_cli_remember_and_memory_commands(demo_dir: Path, tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from glaive.cli import app

    run = CliRunner().invoke
    assert run(app, ["memory", "list"]).exit_code == 1
    a = _case(demo_dir, tmp_path, "Operation A")
    r = run(app, ["remember", str(a.analysis_dir)])
    assert r.exit_code == 0 and "Remembered" in r.output
    b = _case(demo_dir, tmp_path, "Operation B")
    r = run(app, ["remember", str(b.analysis_dir)])
    assert "Seen in earlier cases" in r.output and C2 in r.output
    r = run(app, ["memory", "search", "shadow copies"])
    assert r.exit_code == 0 and "Operation" in r.output
    assert "Operation A" in run(app, ["memory", "list"]).output
    r = run(app, ["memory", "forget", "Operation A"])
    assert "Forgot" in r.output and "Operation A" not in run(app, ["memory", "list"]).output


@pytest.mark.parametrize("value", ["off", "0", "no"])
def test_memory_off_values(value: str) -> None:
    assert memory_path({"GLAIVE_MEMORY": value}) is None
