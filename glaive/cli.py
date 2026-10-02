"""GLAIVE command-line interface.

    glaive demo                      build the demo case, investigate it, score it
    glaive investigate PATH          investigate a file, folder or .zip of evidence
    glaive serve [CASE]              open the web app for a case
    glaive report CASE               (re)write report.html and report.md
    glaive verify CASE               re-check the SHA-256 of every evidence file
    glaive models                    show which AI models GLAIVE can use
    glaive eval CASE --key FILE      score a case against an answer key
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
    """shutil.rmtree that also removes read-only files (evidence copies are
    read-only, and Windows refuses to delete read-only files otherwise)."""
    import os
    import shutil
    import stat

    def make_writable_and_retry(func, target, _exc):  # noqa: ANN001
        os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        func(target)

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=make_writable_and_retry)
    else:
        shutil.rmtree(path, onerror=make_writable_and_retry)


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
        serve(out / "case")


@app.command()
def serve(
    case: Path = typer.Argument(Path("cases/new-case"), help="Case folder (created if new)."),
    host: str = typer.Option("127.0.0.1", help="Address to listen on."),
    port: int = typer.Option(8765, help="Port."),
    no_browser: bool = typer.Option(False, help="Do not open a browser."),
) -> None:
    """Open the web app for a case."""
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
    uvicorn.run(create_app(session, token=token), host=host, port=port, log_level="warning")


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
