"""Benchmark harness: dataset labels, scoring, results and the CLI."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from glaive.bench import BenchCase, load, run_benchmark, run_case, stratified
from glaive.bench.compare import compare_markdown, load_results
from glaive.bench.datasets import _techniques_from_name
from glaive.detection.sigma import load_rules


def _otrf_tree(root: Path, demo_dir: Path) -> Path:
    """A miniature OTRF checkout: one Windows dataset whose host zip holds the
    demo case, labelled as LSASS credential dumping."""
    meta = root / "datasets" / "atomic" / "_metadata"
    host = root / "datasets" / "atomic" / "windows" / "credential_access" / "host"
    meta.mkdir(parents=True)
    host.mkdir(parents=True)
    with zipfile.ZipFile(host / "lsass_dump.zip", "w") as z:
        for f in sorted(demo_dir.glob("*.jsonl")):
            z.write(f, f.name)
    (meta / "SDWIN-1.yaml").write_text("""
title: LSASS dump
id: SDWIN-1
platform: [Windows]
attack_mappings:
  - technique: T1003
    sub-technique: "001"
    tactics: [TA0006]
files:
  - type: Host
    link: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/lsass_dump.zip
  - type: Network
    link: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/network/missing.zip
""", encoding="utf-8")
    (meta / "SDLIN-1.yaml").write_text("platform: [Linux]\nid: SDLIN-1\n", encoding="utf-8")
    return root


def test_evtx_attack_samples_labels_come_from_folders(tmp_path: Path) -> None:
    for rel in ["Credential Access/CA_dump_t1003.001.evtx", "Defense Evasion/x.evtx",
                "Other/unlabelled.evtx", "AutomatedTestingTools/y.evtx", "root.evtx"]:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"")
    cases = load("evtx-attack-samples", tmp_path)
    assert {c.id: (c.tactics, c.techniques) for c in cases} == {
        "Credential Access/CA_dump_t1003.001.evtx": (["TA0006"], ["T1003.001"]),
        "Defense Evasion/x.evtx": (["TA0005"], []),
    }


def test_technique_ids_in_file_names() -> None:
    assert _techniques_from_name("4794_DSRM_password_change_t1098") == ["T1098"]
    assert _techniques_from_name("sysmon_T1003_001_lsass") == ["T1003.001"]
    assert _techniques_from_name("Sysmon13_MachineAccount") == []


def test_otrf_labels_from_metadata(tmp_path: Path, demo_dir: Path) -> None:
    cases = load("otrf", _otrf_tree(tmp_path / "otrf", demo_dir))
    assert len(cases) == 1  # the Linux dataset and the missing network zip are ignored
    c = cases[0]
    assert (c.id, c.tactics, c.techniques, len(c.paths)) == ("SDWIN-1", ["TA0006"],
                                                              ["T1003.001"], 1)


def test_benign_machines_from_archives_and_folders(tmp_path: Path) -> None:
    import tarfile

    (tmp_path / "win10" / "Logs").mkdir(parents=True)
    (tmp_path / "win10" / "Logs" / "Security.evtx").write_bytes(b"")
    with tarfile.open(tmp_path / "win11-client.tgz", "w:gz"):
        pass
    (tmp_path / "readme.txt").write_text("x", encoding="utf-8")
    assert [c.id for c in load("benign", tmp_path)] == ["win10", "win11-client.tgz"]
    assert [c.id for c in load("benign", tmp_path / "win11-client.tgz")] == ["win11-client.tgz"]
    assert all(c.benign for c in load("benign", tmp_path))


def test_unknown_or_empty_dataset_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown dataset"):
        load("nope", tmp_path)
    with pytest.raises(ValueError, match="No otrf cases"):
        load("otrf", tmp_path)


def test_stratified_sample_covers_every_tactic() -> None:
    cases = [BenchCase(f"{t}{i}", "x", [], tactics=[t]) for t in ("A", "B", "C") for i in range(5)]
    picked = stratified(cases, 4)
    assert len(picked) == 4 and {c.tactics[0] for c in picked} == {"A", "B", "C"}
    assert stratified(cases, None) == cases and stratified(cases, 4) == picked


def test_run_case_scores_the_demo_attack(demo_dir: Path) -> None:
    rules, _ = load_rules()
    case = BenchCase("demo", "test", [demo_dir], tactics=["TA0006"], techniques=["T1003"])
    r = run_case(case, rules)
    assert r.error is None and r.events > 200 and r.alerts > 10 and r.findings > 5
    assert r.tactic_hit("alerts") and r.tactic_hit("findings")
    assert r.technique_hit("findings")  # comsvcs MiniDump -> T1003.001 ~ T1003
    miss = run_case(BenchCase("demo", "test", [demo_dir], tactics=["TA0010"]), rules)
    assert not miss.tactic_hit("findings")  # nothing about exfiltration in the demo


def test_a_broken_case_is_recorded_not_raised(tmp_path: Path) -> None:
    rules, _ = load_rules()
    r = run_case(BenchCase("gone", "test", [tmp_path / "missing"]), rules)
    assert r.error and r.seconds >= 0


def test_benchmark_result_aggregates_and_compares(tmp_path: Path, demo_dir: Path) -> None:
    attack = BenchCase("demo", "test", [demo_dir], tactics=["TA0006"], techniques=["T1003"])
    clean = BenchCase("clean", "test", [demo_dir], benign=True)  # pretend: all alarms are false
    res = run_benchmark([attack, clean], dataset="test")
    d = res.to_dict()
    assert d["summary"]["findings"]["tactic"] == {"hits": 1, "total": 1}
    assert d["false_alarms"]["machines"] == 1 and d["false_alarms"]["alerts"] > 0
    assert d["per_tactic"]["alerts"][0]["name"] == "Credential Access"
    md = res.to_markdown()
    assert "Right ATT&CK tactic" in md and "false alarms" in md
    f = tmp_path / "r.json"
    f.write_text(json.dumps(d, default=str), encoding="utf-8")
    table = compare_markdown(load_results([f]))
    assert "rules only" in table and "100%" in table


def test_ai_mode_needs_a_model(demo_dir: Path) -> None:
    with pytest.raises(RuntimeError, match="needs a configured model"):
        run_benchmark([BenchCase("d", "t", [demo_dir])], dataset="t", mode="ai",
                      router_factory=lambda: None)


def test_ai_mode_runs_the_agent_team(demo_dir: Path) -> None:
    from glaive.llm import Message, Router, ScriptedProvider

    def factory() -> Router:  # a model that finishes at once: findings come from triage
        def reply(messages, tools):  # noqa: ANN001, ANN202
            return Message("assistant", '{"verdict": "upheld", "argument": "ok", '
                                        '"alternative_explanation": null}')
        return Router([ScriptedProvider(reply)])

    res = run_benchmark([BenchCase("d", "t", [demo_dir], tactics=["TA0006"])], dataset="t",
                        mode="ai", router_factory=factory, max_steps=2)
    assert res.model == "scripted:scripted-1" and res.cases[0].error is None
    assert res.cases[0].tokens > 0 and res.cases[0].tactic_hit("findings")


def test_cli_bench_run_and_compare(tmp_path: Path, demo_dir: Path) -> None:
    from typer.testing import CliRunner

    from glaive.cli import app

    root = _otrf_tree(tmp_path / "otrf", demo_dir)
    out = tmp_path / "results"
    r = CliRunner().invoke(app, ["bench", "run", "otrf", str(root), "--out", str(out)])
    assert r.exit_code == 0, r.output
    saved = list(out.glob("otrf-rules-*.json"))
    assert len(saved) == 1 and list(out.glob("otrf-rules-*.md"))
    r = CliRunner().invoke(app, ["bench", "compare", str(saved[0])])
    assert r.exit_code == 0 and "rules only" in r.output
    r = CliRunner().invoke(app, ["bench", "run", "otrf", str(tmp_path / "nothing")])
    assert r.exit_code == 2
