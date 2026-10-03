"""GLAIVE command-line interface.

    glaive demo                      build the demo case, investigate it, score it
    glaive investigate PATH          investigate a file, folder or .zip of evidence
    glaive serve [CASE]              open the web app for a case
    glaive report CASE               (re)write report.html and report.md
    glaive verify CASE               re-check the SHA-256 of every evidence file
    glaive models                    show which AI models GLAIVE can use
    glaive eval CASE --key FILE      score a case against an answer key
    glaive trace CASE                every model and tool call of a case (audit trail)
    glaive search CASE "QUERY"       search the evidence in plain words
    glaive ask CASE "QUESTION"       answer from findings and evidence, with citations
    glaive remember CASE             add a case's findings to past-case memory (local)
    glaive memory search|list|forget search or manage past-case memory
    glaive bench run DATASET PATH    benchmark on a public dataset (rules or AI)
    glaive bench compare FILES...    rules alone vs each model, side by side
    glaive bench retrieval           recall@k of evidence search on the demo case
    glaive mcp [--case CASE]         run the MCP server (Claude Code, Cursor, Dify...)
"""
from __future__ import annotations

import json
import re
import sys
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from glaive import __version__

for _stream in (sys.stdout, sys.stderr):  # never crash on a non-UTF-8 Windows console
    try:
        _stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass

app = typer.Typer(
    name="glaive",
    help="Graph-Linked Adversarial Investigation & Verification Engine.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(highlight=False)

LEVEL_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan",
               "info": "dim"}


def _remove_tree(path: Path) -> None:
    from glaive.fsutil import remove_tree

    remove_tree(path)


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower() or "case"


def _write_reports(session, eval_md: str | None = None) -> tuple[Path, Path]:  # noqa: ANN001
    from glaive.reporting.html import render_html

    html_path = session.analysis_dir / "report.html"
    md_path = session.analysis_dir / "report.md"
    html_path.write_text(render_html(session, eval_markdown=eval_md), encoding="utf-8")
    md_path.write_text((session.summary_markdown or "") + "\n\n" + session.report.to_markdown(),
                       encoding="utf-8")
    return html_path, md_path


def _print_findings(session) -> None:  # noqa: ANN001
    from glaive.agents.agents import numbered_findings

    rows = numbered_findings(session)
    if not rows:
        console.print("[dim]No findings.[/]")
        return
    t = Table(show_lines=False, header_style="bold")
    t.add_column("Ref")
    t.add_column("Severity")
    t.add_column("Confidence")
    t.add_column("Status")
    t.add_column("Claim", overflow="fold")
    for fid, f in rows[:40]:
        t.add_row(fid, f"[{LEVEL_STYLE.get(f.severity, '')}]{f.severity}[/]", f.confidence,
                  f.status.replace("_", " "), f.claim[:220])
    console.print(t)
    if len(rows) > 40:
        console.print(f"[dim]... and {len(rows) - 40} more in the report.[/]")


def _run(evidence: Path, out: Path, name: str | None, offline: bool, language: str,
         max_steps: int, sigma: list[Path], skeptic: bool):  # noqa: ANN202
    from glaive.agents import Investigation
    from glaive.ingestion.pipeline import ingest_path
    from glaive.llm import router_from_env
    from glaive.mcp_server.session import GlaiveSession

    session = GlaiveSession(analysis_dir=out, case_name=name or evidence.resolve().name)
    with console.status("Reading evidence..."):
        summary = ingest_path(session, evidence, sigma_paths=sigma)
    ingested = sum(1 for f in summary.files if f.status == "ingested")
    console.print(f"Evidence: [bold]{ingested}[/] file(s) parsed, "
                  f"{len(summary.files) - ingested} stored without parsing, "
                  f"[bold]{summary.events_total}[/] events, [bold]{summary.alerts}[/] detections "
                  f"({', '.join(f'{v} {k}' for k, v in sorted(summary.alerts_by_level.items()))}) "
                  f"in {summary.seconds:.1f}s")
    router = None if offline else router_from_env()
    if router:
        console.print(f"AI investigators: [bold]{router.describe()}[/]")
    else:
        console.print("[yellow]No AI model configured (or --offline): running detection rules "
                      "only. Run 'glaive models' to see how to add one.[/]")
    with console.status("Investigating..."):
        result = Investigation(session, router, max_steps=max_steps, skeptic=skeptic,
                               language=language).run()
    return session, result


@app.command()
def version() -> None:
    """Print GLAIVE version."""
    console.print(f"glaive {__version__}")


@app.command()
def investigate(
    evidence: Path = typer.Argument(..., help="Evidence file, folder or .zip."),
    out: Path = typer.Option(None, "--out", "-o", help="Case folder (default ./cases/<name>)."),
    name: str = typer.Option(None, help="Case name."),
    offline: bool = typer.Option(False, help="Do not use any AI model, rules only."),
    language: str = typer.Option("en", help="Report language: en or zh."),
    max_steps: int = typer.Option(30, help="Maximum tool calls for the Hunter agent."),
    sigma: list[Path] = typer.Option([], help="Extra Sigma rule folder (repeatable)."),
    skeptic: bool = typer.Option(True, help="Let the Skeptic agent challenge findings."),
    open_report: bool = typer.Option(False, "--open", help="Open the HTML report when done."),
) -> None:
    """Investigate evidence end to end and write a verified report."""
    if not evidence.exists():
        console.print(f"[red]Evidence not found:[/] {evidence}")
        raise typer.Exit(code=2)
    out = out or Path("cases") / _slug(name or evidence.resolve().name)
    session, result = _run(evidence, out, name, offline, language, max_steps, sigma, skeptic)
    _print_findings(session)
    html_path, _ = _write_reports(session)
    pending = result.findings_pending
    console.print(f"\nCase saved to [bold]{session.case_path}[/]")
    console.print(f"Report: [bold]{html_path}[/]")
    if result.llm:
        console.print(f"Tokens used: {result.llm['tokens_used']}")
    if pending:
        console.print(f"[yellow]{pending} high-severity finding(s) await analyst approval: "
                      f"glaive serve {out}[/]")
    from glaive.memory import open_memory

    mem = open_memory()
    if mem is not None:
        with mem:
            _print_overlaps(mem.overlaps(session))
    if open_report:
        webbrowser.open(html_path.resolve().as_uri())


@app.command()
def demo(
    out: Path = typer.Option(Path("glaive-demo"), "--out", "-o", help="Where to create the demo."),
    offline: bool = typer.Option(False, help="Rules only, even if a model is configured."),
    language: str = typer.Option("en", help="Report language: en or zh."),
    serve_after: bool = typer.Option(False, "--serve", help="Open the web app afterwards."),
) -> None:
    """Create a realistic intrusion case, investigate it and score the result."""
    from glaive.demo.case import ANSWER_KEY, write_demo_case
    from glaive.eval import score_session

    if out.exists():
        _remove_tree(out)
    evidence = out / "evidence"
    files = write_demo_case(evidence)
    console.print(f"Demo evidence written: {len(files)} log exports in {evidence}")
    session, _ = _run(evidence, out / "case", "Operation Invoice (demo)", offline, language,
                      30, [], True)
    _print_findings(session)
    ev = score_session(session, ANSWER_KEY)
    console.print("\n[bold]Score against the answer key[/]")
    console.print(f"  Recall: [bold]{ev.recall:.0%}[/] of the attack steps found "
                  f"({sum(i.found for i in ev.items)}/{len(ev.items)})")
    missed = [i.title for i in ev.items if not i.found]
    if missed:
        console.print("  Missed: " + "; ".join(missed))
    console.print(f"  Claims blocked by the gate: {ev.blocked}")
    console.print(f"  Ungrounded statements in the report: {ev.ungrounded_in_report}")
    html_path, _ = _write_reports(session, ev.to_markdown())
    console.print(f"\nReport: [bold]{html_path}[/]")
    if serve_after:
        _serve(out / "case")


@app.command()
def serve(
    case: Path = typer.Argument(Path("cases/new-case"), help="Case folder (created if new)."),
    host: str = typer.Option("127.0.0.1", help="Address to listen on."),
    port: int = typer.Option(8765, help="Port."),
    no_browser: bool = typer.Option(False, help="Do not open a browser."),
) -> None:
    """Open the web app for a case."""
    _serve(case, host, port, no_browser)


def _serve(case: Path, host: str = "127.0.0.1", port: int = 8765,
           no_browser: bool = False) -> None:
    # Plain function so other commands can call it: calling a Typer command directly
    # would pass its typer.Option(...) defaults instead of real values.
    import secrets

    import uvicorn

    from glaive.mcp_server.session import CASE_FILENAME, GlaiveSession
    from glaive.web.app import create_app

    session = GlaiveSession.load(case) if (case / CASE_FILENAME).exists() else \
        GlaiveSession(analysis_dir=case)
    token = None
    if host not in ("127.0.0.1", "localhost", "::1"):
        import os

        token = os.environ.get("GLAIVE_WEB_TOKEN") or secrets.token_urlsafe(16)
        console.print(f"[yellow]Listening beyond this computer: access token required.[/]\n"
                      f"  token: [bold]{token}[/]")
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    if ":" in shown:  # IPv6 literals need brackets in a URL
        shown = f"[{shown}]"
    url = f"http://{shown}:{port}/" + (f"?token={token}" if token else "")
    console.print(f"GLAIVE web app for [bold]{session.case_name}[/]: {url}")
    if not no_browser:
        webbrowser.open(url)
    from glaive.web.app import shutting_down

    class _Server(uvicorn.Server):
        def handle_exit(self, sig: int, frame: object) -> None:  # noqa: D102
            shutting_down.set()
            super().handle_exit(sig, frame)

    shutting_down.clear()
    config = uvicorn.Config(create_app(session, token=token), host=host, port=port,
                            log_level="warning", timeout_graceful_shutdown=3)
    _Server(config).run()


@app.command()
def report(case: Path = typer.Argument(..., help="Case folder.")) -> None:
    """Rewrite report.html and report.md for a saved case."""
    from glaive.mcp_server.session import GlaiveSession

    session = GlaiveSession.load(case)
    html_path, md_path = _write_reports(session)
    console.print(f"Wrote {html_path} and {md_path}")


@app.command()
def verify(case: Path = typer.Argument(..., help="Case folder.")) -> None:
    """Re-hash every evidence file and compare with the hash recorded at intake."""
    from glaive.mcp_server.session import GlaiveSession

    session = GlaiveSession.load(case)
    results = session.store.verify_all()
    bad = [h for h, ok in results.items() if not ok]
    for h in bad:
        console.print(f"[red]CHANGED[/] {session.store.get_metadata(h)['original_name']} ({h})")
    console.print(f"{len(results) - len(bad)}/{len(results)} evidence files intact.")
    raise typer.Exit(code=1 if bad else 0)


@app.command()
def models() -> None:
    """Show which AI models are configured and how to add one."""
    from glaive.llm.catalog import PRESETS, detect_providers

    active = detect_providers()
    t = Table(header_style="bold")
    t.add_column("Provider")
    t.add_column("Set this")
    t.add_column("Default model")
    t.add_column("Status")
    for p in PRESETS.values():
        env = p.key_env or ("OLLAMA_MODEL" if p.name == "ollama" else "GLAIVE_BASE_URL + GLAIVE_MODEL")
        status = "[green]active[/]" if p.name in active else ""
        t.add_row(p.label, env, p.default_model or "-", status)
    console.print(t)
    if active:
        console.print(f"Fallback order: {' -> '.join(active)}  (change with GLAIVE_PROVIDERS)")
    else:
        console.print("No model configured. GLAIVE still works with its detection rules.\n"
                      "Example (PowerShell):  $env:DEEPSEEK_API_KEY = 'sk-...'\n"
                      "Example (bash):        export ANTHROPIC_API_KEY=sk-ant-...\n"
                      "Fully offline:         ollama pull qwen3:8b; set OLLAMA_MODEL=qwen3:8b")
    from glaive.security.privacy import privacy_mode

    console.print({
        "pseudonymize": "Privacy: cloud models see tokens (USER_1, HOST_2...) instead of your "
                        "account names, hosts, internal IPs and SIDs. Local models see real data.",
        "local-only": "Privacy: local-only. Cloud models are never used.",
        "off": "[yellow]Privacy: off. Case data is sent to cloud models unchanged.[/]",
    }[privacy_mode()] + "  (GLAIVE_PRIVACY)")


@app.command("eval")
def eval_cmd(case: Path = typer.Argument(..., help="Case folder."),
             key: Path = typer.Option(..., help="Answer key JSON.")) -> None:
    """Score a saved case against an answer key."""
    from glaive.eval import score_session
    from glaive.eval.scoring import load_answer_key
    from glaive.mcp_server.session import GlaiveSession

    session = GlaiveSession.load(case)
    result = score_session(session, load_answer_key(key))
    console.print(result.to_markdown())
    console.print(json.dumps(result.to_dict(), indent=2)[:4000])


@app.command()
def search(case: Path = typer.Argument(..., help="Case folder."),
           query: str = typer.Argument(..., help='e.g. "credential dumping"'),
           limit: int = typer.Option(10, help="Number of results."),
           mode: str = typer.Option("hybrid", help="hybrid, bm25 or dense."),
           node_type: str = typer.Option(None, help="Only this node type, e.g. Process.")) -> None:
    """Search a case's evidence graph (keyword + vector, see GLAIVE_EMBED)."""
    from glaive.mcp_server.session import GlaiveSession
    from glaive.retrieval import RetrievalConfigError, RetrievalError, configured_models
    from glaive.retrieval.index import index_for

    session = GlaiveSession.load(case)
    try:
        embedder, reranker = configured_models()
        idx = index_for(session, embedder, reranker)
        hits = idx.search(query, limit, mode=mode, node_type=node_type)
    except (RetrievalError, RetrievalConfigError, ValueError) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(2) from e
    info = idx.info()
    console.print(f"{info['documents']} nodes indexed, {info['vectors']} with vectors "
                  f"({info['embedder'] or 'keyword search only; set GLAIVE_EMBED for vectors'}).")
    t = Table(header_style="bold")
    for col in ("#", "Type", "Node", "Found by"):
        t.add_column(col)
    for i, h in enumerate(hits, 1):
        t.add_row(str(i), h.node_type, h.label[:70],
                  ", ".join(f"{k} #{v}" for k, v in h.ranks.items()))
    console.print(t)


@app.command()
def ask(case: Path = typer.Argument(..., help="Case folder."),
        question: str = typer.Argument(..., help='e.g. "did the attacker reach the file server?"'),
        language: str = typer.Option("en", help="en or zh."),
        offline: bool = typer.Option(False, help="No model: list matching findings and evidence.")
        ) -> None:
    """Answer a question about a case. Every sentence cites a finding [F#] or an
    evidence node [E#] and is checked against it; unverifiable sentences are removed."""
    from glaive.agents.ask import ask as ask_case
    from glaive.mcp_server.session import GlaiveSession

    session = GlaiveSession.load(case)
    out = ask_case(session, question, language, use_model=not offline)
    console.print(out["answer"])
    for cid, c in out["citations"].items():
        what = c.get("claim") if c["kind"] == "finding" else f"{c['node_type']}: {c['label']}"
        console.print(f"  [dim][{cid}] {what}[/]")
    if out["removed"]:
        console.print(f"[yellow]{len(out['removed'])} sentence(s) could not be verified and "
                      f"were removed.[/]")
    session.save()


@app.command()
def trace(case: Path = typer.Argument(..., help="Case folder."),
          as_json: bool = typer.Option(False, "--json", help="Print the summary as JSON.")) -> None:
    """Show the audit trail: model calls, tokens, tool calls and gate decisions."""
    from glaive.observability import read_trace, summarize

    spans = read_trace(case / "trace.jsonl")
    if not spans:
        console.print(f"No trace in {case} yet (it is written while an investigation runs).")
        raise typer.Exit(1)
    s = summarize(spans)
    if as_json:
        console.print_json(json.dumps(s))
        return
    console.print(f"{s['spans']} spans from {s['investigations']} investigation run(s), "
                  f"{s['errors']} error(s).")
    t = Table(header_style="bold", title="Model calls")
    for col in ("Model", "Calls", "Input tokens", "Output tokens", "Time"):
        t.add_column(col)
    for m, row in s["models"].items():
        t.add_row(m, str(int(row["calls"])), f"{int(row['input_tokens']):,}",
                  f"{int(row['output_tokens']):,}", f"{row['ms'] / 1000:.1f}s")
    console.print(t)
    if s["tools"]:
        console.print("Tool calls: " + ", ".join(f"{k} {v}" for k, v in
                                                 sorted(s["tools"].items(), key=lambda kv: -kv[1])))
    if s["gate_decisions"]:
        console.print("Gate decisions: " + ", ".join(f"{k} {v}" for k, v in
                                                     s["gate_decisions"].items()))


@app.command()
def remember(case: Path = typer.Argument(..., help="Case folder.")) -> None:
    """Add a case's findings to past-case memory on this computer (opt-in)."""
    from glaive.mcp_server.session import GlaiveSession
    from glaive.memory import memory_path, open_memory

    mem = open_memory(create=True)
    if mem is None:
        console.print("Memory is off (GLAIVE_MEMORY=off).")
        raise typer.Exit(1)
    session = GlaiveSession.load(case)
    with mem:
        n = mem.remember(session)
        overlaps = mem.overlaps(session)
    console.print(f"Remembered {n} finding(s) of {session.case_name!r} in {memory_path()}.")
    _print_overlaps(overlaps)


def _print_overlaps(overlaps: list[dict]) -> None:
    if not overlaps:
        return
    console.print("[bold]Seen in earlier cases:[/]")
    for o in overlaps[:20]:
        console.print(f"  {o['indicator']} ({o['finding']}) also in {o['past_case']!r} "
                      f"({o['past_date']}): {o['past_claim'][:120]}")


memory_app = typer.Typer(help="Past-case memory (local, opt-in).", no_args_is_help=True)
app.add_typer(memory_app, name="memory")


@memory_app.command("search")
def memory_search(query: str = typer.Argument(...),
                  limit: int = typer.Option(10, help="Number of results.")) -> None:
    """Search findings remembered from earlier cases."""
    from glaive.memory import open_memory

    mem = open_memory()
    if mem is None:
        console.print("Nothing remembered yet. Use: glaive remember CASE")
        raise typer.Exit(1)
    with mem:
        rows = mem.search(query, limit)
    for r in rows:
        console.print(f"[bold]{r.case_name}[/] ({r.committed_at[:10]}, {r.severity}) {r.claim}")
    if not rows:
        console.print("No match.")


@memory_app.command("list")
def memory_list() -> None:
    """Cases in memory."""
    from glaive.memory import open_memory

    mem = open_memory()
    if mem is None:
        console.print("Nothing remembered yet. Use: glaive remember CASE")
        raise typer.Exit(1)
    with mem:
        for c in mem.cases():
            console.print(f"{c['case_name']}: {c['findings']} finding(s), "
                          f"remembered {c['remembered_at']}")


@memory_app.command("forget")
def memory_forget(case_name: str = typer.Argument(..., help="Case name as listed.")) -> None:
    """Remove a case from memory."""
    from glaive.memory import open_memory

    mem = open_memory()
    if mem is None:
        raise typer.Exit(1)
    with mem:
        n = mem.forget(case_name)
    console.print(f"Forgot {n} finding(s) of {case_name!r}.")


bench_app = typer.Typer(help="Benchmarks on public datasets.", no_args_is_help=True)
app.add_typer(bench_app, name="bench")


@bench_app.command("run")
def bench_run(
    dataset: str = typer.Argument(..., help="evtx-attack-samples, otrf or benign."),
    path: Path = typer.Argument(..., help="Local copy of the dataset."),
    mode: str = typer.Option("rules", help="rules (no model) or ai (configured model)."),
    sigma: list[Path] = typer.Option(None, help="Extra Sigma rules, e.g. sigma/rules/windows."),
    limit: int = typer.Option(None, help="Only this many cases, spread across tactics."),
    max_steps: int = typer.Option(20, help="Agent steps per case (ai mode)."),
    out: Path = typer.Option(Path("bench-results"), help="Where to write the results."),
) -> None:
    """Score GLAIVE against a public dataset's own labels."""
    from datetime import UTC, datetime

    from glaive.bench import load, run_benchmark, stratified
    from glaive.llm import router_from_env

    try:
        cases = stratified(load(dataset, path), limit)
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(2) from e
    if mode == "ai" and router_from_env() is None:
        console.print("[red]ai mode needs a model. Run 'glaive models' to set one up.[/]")
        raise typer.Exit(2)
    console.print(f"{len(cases)} {dataset} cases, mode {mode}")

    def progress(i: int, n: int, r) -> None:  # noqa: ANN001
        if i == n or i % 25 == 0:
            console.print(f"  {i}/{n}")
        if r.error:
            console.print(f"  [yellow]{r.id}: {r.error}[/]")

    result = run_benchmark(cases, dataset=dataset, mode=mode, sigma_paths=list(sigma or []),
                           router_factory=router_from_env, max_steps=max_steps,
                           progress=progress)
    out.mkdir(parents=True, exist_ok=True)
    who = "rules" if mode == "rules" else _slug(result.model or "ai")[:40]
    stem = f"{dataset}-{who}{'-sigma' if sigma else ''}-" \
           f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}"
    (out / f"{stem}.json").write_text(json.dumps(result.to_dict(), indent=1, default=str),
                                      encoding="utf-8")
    (out / f"{stem}.md").write_text(result.to_markdown(), encoding="utf-8")
    console.print(result.to_markdown())
    console.print(f"Saved {out / (stem + '.json')}")


@bench_app.command("retrieval")
def bench_retrieval() -> None:
    """recall@k and MRR of evidence search on the demo case: keyword only, and
    vector + hybrid when GLAIVE_EMBED is set (reranked when GLAIVE_RERANK is)."""
    import tempfile

    from glaive.demo.case import ANSWER_KEY, write_demo_case
    from glaive.ingestion.pipeline import ingest_path
    from glaive.mcp_server.session import GlaiveSession
    from glaive.retrieval import RetrievalConfigError, configured_models
    from glaive.retrieval.evaluate import evaluate, to_markdown
    from glaive.retrieval.index import EvidenceIndex

    try:
        embedder, reranker = configured_models()
    except RetrievalConfigError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(2) from e
    root = Path(tempfile.mkdtemp(prefix="glaive-retrieval-"))
    try:
        write_demo_case(root / "evidence")
        session = GlaiveSession(analysis_dir=root / "case")
        ingest_path(session, root / "evidence")
        rows = []
        keyword = EvidenceIndex(root / "case" / "keyword.sqlite")
        keyword.build(session.graph)
        rows.append(evaluate(keyword, ANSWER_KEY, mode="bm25"))
        keyword.close()
        if embedder is not None:
            idx = EvidenceIndex(root / "case" / "hybrid.sqlite", embedder, reranker)
            idx.build(session.graph)
            rows.append(evaluate(idx, ANSWER_KEY, mode="dense", rerank=False))
            rows.append(evaluate(idx, ANSWER_KEY, mode="hybrid", rerank=False))
            if reranker is not None:
                rows.append(evaluate(idx, ANSWER_KEY, mode="hybrid", rerank=True))
            idx.close()
    finally:
        _remove_tree(root)
    console.print(to_markdown(rows))
    if embedder is None:
        console.print("Keyword search only. Set GLAIVE_EMBED (e.g. fastembed) to compare.")


@bench_app.command("compare")
def bench_compare(files: list[Path] = typer.Argument(..., help="Result .json files.")) -> None:
    """Rules alone vs each model on the same datasets."""
    from glaive.bench.compare import compare_markdown, load_results

    runs = load_results(files)
    if not runs:
        console.print("[red]No benchmark results in those files.[/]")
        raise typer.Exit(2)
    console.print(compare_markdown(runs))


@app.command()
def mcp(case: Path = typer.Option(Path("analysis"), help="Case folder to serve."),
        evidence_root: Path = typer.Option(None, help="Only allow ingesting from here.")) -> None:
    """Run the GLAIVE MCP server over stdio (for Claude Code, Cursor, Dify, Cherry Studio...)."""
    from glaive.mcp_server.server import build_server
    from glaive.mcp_server.session import CASE_FILENAME, GlaiveSession

    session = GlaiveSession.load(case, evidence_root=evidence_root) \
        if (case / CASE_FILENAME).exists() else \
        GlaiveSession(analysis_dir=case, evidence_root=evidence_root)
    build_server(session).run()


if __name__ == "__main__":
    app()
