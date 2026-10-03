"""Ask the case: answers from findings and evidence, every sentence checked."""
from __future__ import annotations

import re

from glaive.agents import RuleInvestigator
from glaive.agents.agents import verify_cited_text
from glaive.agents.ask import ask
from glaive.demo.case import FS
from glaive.llm import Message, Router, ScriptedProvider
from glaive.mcp_server.session import GlaiveSession


def _evidence_ids(messages) -> dict[str, str]:  # noqa: ANN001
    """[E#] -> first line of that evidence document, as the model saw it."""
    user = next(m.content for m in messages if m.role == "user")
    return {m.group(1): m.group(2) for m in re.finditer(r"\[(E\d+)\] (.+)", user or "")}


def test_offline_answer_lists_findings_and_evidence(demo_session: GlaiveSession) -> None:
    RuleInvestigator(demo_session).run()
    out = ask(demo_session, "were shadow copies deleted?", use_model=False)
    assert out["mode"] == "retrieval" and "[F" in out["answer"] and "[E1]" in out["answer"]
    assert out["citations"]["E1"]["kind"] == "evidence"
    assert any(c["kind"] == "finding" for c in out["citations"].values())


def test_offline_answer_without_findings_uses_evidence(demo_session: GlaiveSession) -> None:
    out = ask(demo_session, "vssadmin delete shadows", use_model=False)
    assert "Related evidence:" in out["answer"] and "Volume Shadow" in out["answer"]


def test_model_answer_keeps_only_verified_sentences(demo_session: GlaiveSession) -> None:
    RuleInvestigator(demo_session).run()
    seen = {}

    def model(messages, tools):  # noqa: ANN001, ANN202
        ev = _evidence_ids(messages)
        seen.update(ev)
        shadow = next(i for i, line in ev.items() if "Volume Shadow" in line)
        return Message("assistant", (
            f"Shadow copies were deleted on {FS} with vssadmin [{shadow}]. "
            f"The data was then sent to 198.51.100.77 [{shadow}]. "
            "This also happened on the domain controller [E99]. "
            "Everything is fine."))

    out = ask(demo_session, "were the backups deleted?", router=Router([ScriptedProvider(model)]))
    assert out["mode"] == "ai"
    assert out["answer"].startswith("Shadow copies were deleted on")
    assert "198.51.100.77" not in out["answer"] and "domain controller" not in out["answer"]
    assert len(out["removed"]) == 3  # invented IP, unknown citation, uncited sentence
    assert set(out["citations"]) == {re.search(r"\[(E\d+)\]", out["answer"]).group(1)}
    assert any(e["action"] == "question_answered" for e in demo_session.audit_log)


def test_unverifiable_answer_falls_back_to_the_evidence(demo_session: GlaiveSession) -> None:
    def liar(messages, tools):  # noqa: ANN001, ANN202
        return Message("assistant", "The attacker exfiltrated everything to 198.51.100.23 "
                                    "[E1].")

    out = ask(demo_session, "what did powershell download?",
              router=Router([ScriptedProvider(liar)]))
    assert out["mode"] == "retrieval" and "could not be verified" in out["answer"]
    assert out["removed"]


def test_evidence_citations_in_the_verifier(demo_session: GlaiveSession) -> None:
    proc = next(p for p in demo_session.graph.find_nodes("Process")
                if "vssadmin" in (p.command_line or "").lower())
    evidence = {"E1": proc.canonical_key()}
    text, kept, removed = verify_cited_text(
        "vssadmin.exe ran on FILESRV-01 [E1]. It then contacted 198.51.100.23 [E1]. "
        "A claim [E2].",
        {}, demo_session.graph, evidence)
    assert kept == 1 and "FILESRV-01 [E1]" in text and len(removed) == 2
    # The reporter passes no evidence: [E#] citations are not accepted there.
    assert verify_cited_text("vssadmin.exe ran [E1].", {}, demo_session.graph)[1] == 0


def test_cli_ask_offline(demo_session: GlaiveSession) -> None:
    from typer.testing import CliRunner

    from glaive.cli import app

    RuleInvestigator(demo_session).run()
    demo_session.save()
    r = CliRunner().invoke(app, ["ask", str(demo_session.analysis_dir),
                                 "was the security log cleared?", "--offline"])
    assert r.exit_code == 0, r.output
    assert "[F" in r.output and "[E1]" in r.output


def test_web_ask_returns_citations(demo_session: GlaiveSession) -> None:
    from fastapi.testclient import TestClient

    from glaive.web.app import create_app

    RuleInvestigator(demo_session).run()
    c = TestClient(create_app(demo_session), base_url="http://127.0.0.1:8765")
    r = c.post("/api/ask", json={"question": "was powershell used?"}).json()
    assert r["citations"] and any(v["kind"] == "evidence" for v in r["citations"].values())
