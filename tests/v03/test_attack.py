"""MITRE ATT&CK technique -> tactic lookups."""
from __future__ import annotations

from pathlib import Path

from glaive.detection.attack import (
    same_tactic,
    same_technique,
    table,
    tactic_id,
    tactic_name,
    tactics_for,
    tactics_from_tags,
)
from glaive.detection.sigma import load_rules
from glaive.mcp_server.session import GlaiveSession


def test_table_is_the_official_enterprise_matrix() -> None:
    t = table()
    assert t["source"] == "MITRE ATT&CK Enterprise" and float(t["version"]) >= 19
    assert len(t["techniques"]) > 600 and len(t["tactics"]) >= 14


def test_technique_to_tactic() -> None:
    assert tactics_for("T1003.001") == ["TA0006"]
    assert "TA0002" in tactics_for("t1059.001")
    assert tactics_for("T1059.999") == tactics_for("T1059")  # unknown sub-technique: parent
    assert tactics_for("not-a-technique") == []


def test_tactic_names_old_and_new() -> None:
    assert tactic_id("Credential Access") == tactic_id("credential_access") == "TA0006"
    assert tactic_id("attack.command-and-control") == "TA0011"
    # ATT&CK v19 renamed Defense Evasion to Stealth; old labels still resolve.
    assert tactic_id("Defense Evasion") == tactic_id("attack.defense_evasion") == "TA0005"
    assert tactic_name("TA0005") == "Stealth"
    assert same_tactic("TA0005", "TA0112") and not same_tactic("TA0005", "TA0006")
    assert tactic_id("Not A Tactic") is None and tactic_id("TA9999") is None


def test_tags_and_technique_matching() -> None:
    assert tactics_from_tags(["attack.execution", "attack.t1059.001", "attack.s0002"]) == ["TA0002"]
    assert same_technique("T1003.006", "T1003") and same_technique("T1003", "T1003.001")
    assert not same_technique("T1059.001", "T1003")
    # v19 revoked T1562.001 in favour of T1685; both spellings match.
    assert same_technique("T1562.001", "T1685") and "TA0112" in tactics_for("T1562.001")


def test_every_builtin_rule_has_a_tactic() -> None:
    rules, _ = load_rules()
    assert rules and all(r.mitre_tactics for r in rules), \
        [r.title for r in rules if not r.mitre_tactics]


def test_alerts_carry_tactics(demo_dir: Path, tmp_path: Path) -> None:
    from glaive.ingestion.pipeline import ingest_path

    s = GlaiveSession(analysis_dir=tmp_path / "c")
    ingest_path(s, demo_dir)
    alerts = list(s.graph.find_nodes("Alert"))
    assert alerts and all(a.mitre_tactics for a in alerts)
    dump = next(a for a in alerts if "Credential Dumping" in a.title)
    assert "TA0006" in dump.mitre_tactics
