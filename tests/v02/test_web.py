"""Web app: API, review workflow, uploads and token auth."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from glaive.agents import RuleInvestigator
from glaive.mcp_server.session import GlaiveSession
from glaive.web.app import STATIC, answer_question, create_app

LOCAL = "http://127.0.0.1:8765"


@pytest.fixture
def client(demo_session: GlaiveSession, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "OLLAMA_MODEL",
              "GLAIVE_PROVIDERS", "GLAIVE_BASE_URL", "GLAIVE_WEB_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    RuleInvestigator(demo_session).run()
    return TestClient(create_app(demo_session), base_url=LOCAL)


def test_case_findings_alerts(client: TestClient) -> None:
    c = client.get("/api/case").json()
    assert c["stats"]["findings_committed"] >= 10 and c["models"] is None
    fs = client.get("/api/findings").json()
    assert fs[0]["ref"] == "F1" and fs[0]["severity"] == "critical"
    assert client.get("/api/alerts?min_level=critical").json()


def test_review_flow(client: TestClient, demo_session: GlaiveSession) -> None:
    pending = next(f for f in client.get("/api/findings").json() if f["status"] == "pending_approval")
    r = client.post(f"/api/findings/{pending['finding_id']}/review",
                    json={"approve": False, "reviewer": "lead", "note": "admin activity"})
    assert r.json()["status"] == "rejected_by_analyst"
    raise_conf = client.post(f"/api/findings/{pending['finding_id']}/review",
                             json={"approve": True, "override_confidence": "confirmed"})
    assert raise_conf.status_code == 400
    assert client.post("/api/findings/nope/review", json={"approve": True}).status_code == 404
    assert GlaiveSession.load(demo_session.analysis_dir).report.get(
        pending["finding_id"]).status == "rejected_by_analyst"


def test_node_graph_timeline_evidence(client: TestClient) -> None:
    f = client.get("/api/findings").json()[0]
    n = client.get("/api/node", params={"key": json.dumps(f["supporting_node_keys"][0])}).json()
    assert n["provenance"]["source_evidence"]["original_name"].endswith(".jsonl")
    g = client.get("/api/graph").json()
    assert g["nodes"] and g["edges"]
    assert client.get("/api/timeline").json()
    v = client.post("/api/evidence/verify").json()
    assert v["failed"] == [] and v["ok"] == 7
    assert client.get("/api/node", params={"key": "[\"Process\",\"x\"]"}).status_code == 404
    assert client.get("/api/node", params={"key": "not json"}).status_code == 400


def test_ask_without_model_uses_retrieval(client: TestClient) -> None:
    r = client.post("/api/ask", json={"question": "were shadow copies deleted?"}).json()
    assert r["mode"] == "retrieval" and "Shadow" in r["answer"] and "[F" in r["answer"]


def test_upload_and_ingest(tmp_path: Path, demo_dir: Path) -> None:
    s = GlaiveSession(analysis_dir=tmp_path / "case")
    c = TestClient(create_app(s), base_url=LOCAL)
    files = [("files", (p.name, p.read_bytes(), "application/json")) for p in demo_dir.iterdir()]
    files.append(("files", ("../../etc/evil name!.jsonl", b"{}", "application/json")))
    r = c.post("/api/upload", files=files).json()
    assert "evil name_.jsonl" in r["saved"] and not any("/" in n for n in r["saved"])
    for _ in range(100):
        if c.get("/api/case").json()["job"] is None and s.graph.node_count():
            break
        time.sleep(0.05)
    assert s.graph.type_counts().get("Alert", 0) >= 15
    inv = c.post("/api/investigate", json={"mode": "offline"}).json()
    assert inv["mode"] == "offline"


def test_token_required_when_configured(demo_session: GlaiveSession) -> None:
    c = TestClient(create_app(demo_session, token="s3cret"))
    assert c.get("/api/case").status_code == 401
    assert c.get("/api/case", headers={"X-Glaive-Token": "s3cret"}).status_code == 200
    assert c.get("/api/case?token=wrong").status_code == 401
    assert c.get("/").status_code == 200  # the page itself is public; data is not


def test_answer_question_without_findings(tmp_path: Path) -> None:
    assert answer_question(GlaiveSession(analysis_dir=tmp_path), "anything")["answer"]


def test_dns_rebinding_is_refused(demo_session: GlaiveSession) -> None:
    c = TestClient(create_app(demo_session), base_url="http://evil.example:8765")
    assert c.get("/api/findings").status_code == 403
    for host in ("127.0.0.1:8765", "localhost:8765", "[::1]:8765"):
        assert c.get("/api/case", headers={"Host": host}).status_code == 200


def test_cross_site_post_is_refused(tmp_path: Path) -> None:
    s = GlaiveSession(analysis_dir=tmp_path / "case")
    c = TestClient(create_app(s), base_url=LOCAL)
    files = [("files", ("a.jsonl", b"{}", "application/json"))]
    r = c.post("/api/upload", files=files, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and not (tmp_path / "case" / "uploads").exists()
    assert c.post("/api/evidence/verify", headers={"Origin": "null"}).status_code == 403
    # the app's own page (same origin) and non-browser clients (no Origin) are allowed
    assert c.post("/api/evidence/verify", headers={"Origin": LOCAL}).status_code == 200
    assert c.post("/api/evidence/verify").status_code == 200


def test_token_mode_allows_remote_hosts(demo_session: GlaiveSession) -> None:
    c = TestClient(create_app(demo_session, token="s3cret"), base_url="http://10.0.0.5:8765")
    assert c.get("/api/case", headers={"X-Glaive-Token": "s3cret"}).status_code == 200


def test_page_makes_no_third_party_requests() -> None:
    """Analysts often work offline or on isolated networks: the UI must not
    load fonts, scripts or styles from anywhere else."""
    page = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "http://" not in page and "https://" not in page


def test_event_stream_ends_when_server_shuts_down(client: TestClient) -> None:
    # An open browser tab must not keep Ctrl+C waiting.
    from glaive.web import app as web

    web.shutting_down.set()
    try:
        r = client.get("/api/events")
        assert r.status_code == 200 and r.text.startswith("data: ")
    finally:
        web.shutting_down.clear()
