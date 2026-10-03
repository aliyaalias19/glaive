"""Self-contained HTML investigation report (one file, no external assets).

Every finding links to its evidence: the cited graph nodes, the log record
each came from (derivation) and the SHA-256 of the original evidence file.
The evidence table at the end lets anyone re-verify those hashes.
"""
from __future__ import annotations

import html
import re
from datetime import UTC, datetime
from typing import Any

from glaive import __version__
from glaive.agents.agents import numbered_findings
from glaive.mcp_server.tools import _node_summary
from glaive.reporting.report import Finding

_SEV_COLOR = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#475467",
              "info": "#667085"}
_CONF_LABEL = {"confirmed": "Confirmed (2+ independent sources)",
               "suspected": "Suspected (1 source)", "inferred": "Inferred (no corroborating record)",
               "disputed": "Disputed (sources disagree or challenged)"}


def _e(x: Any) -> str:
    return html.escape("" if x is None else str(x))


def markdown_to_html(md: str) -> str:
    """Tiny, safe markdown renderer: headings, bullets, bold, code, paragraphs."""
    out: list[str] = []
    in_list = False
    for raw in md.splitlines():
        line = raw.rstrip()
        if not line:
            if in_list:
                out.append("</ul>")
                in_list = False
            continue
        text = _e(line)
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
        text = re.sub(r"\[(F\d+)\]", r'<a class="cite" href="#\1">\1</a>', text)
        m = re.match(r"^(#{1,4})\s+(.*)", text)
        if m:
            if in_list:
                out.append("</ul>")
                in_list = False
            level = min(len(m.group(1)) + 1, 5)
            out.append(f"<h{level}>{m.group(2)}</h{level}>")
            continue
        m = re.match(r"^\s*([-*]|\d+\.)\s+(.*)", text)
        if m:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{m.group(2)}</li>")
            continue
        out.append(f"<p>{text}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def _evidence_rows(session: Any, f: Finding) -> str:
    rows = []
    for key in f.supporting_node_keys:
        k = tuple(key)
        if not session.graph.has_node(k):
            continue
        node = session.graph.get_node(k)
        s = _node_summary(node)
        label = (s.get("title") or s.get("name") or s.get("threat_name") or s.get("full_path")
                 or s.get("hostname") or s.get("username") or s.get("remote_addr") or k[0])
        meta = session.store.get_metadata(node.evidence_hash) if session.store.has(
            node.evidence_hash) else {}
        rows.append(
            f"<tr><td>{_e(k[0])}</td><td>{_e(label)}</td><td>{_e(node.derivation)}</td>"
            f"<td>{_e(meta.get('original_name', '-'))}<br><code class='hash'>"
            f"{_e(node.evidence_hash[:16])}...</code></td></tr>")
    return "".join(rows)


def render_html(session: Any, summary_markdown: str | None = None,
                eval_markdown: str | None = None) -> str:
    rows = numbered_findings(session)
    counts: dict[str, int] = {}
    for _, f in rows:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    cards = []
    for fid, f in rows:
        tags = "".join(f"<span class='tag'>{_e(t)}</span>" for t in f.mitre_techniques)
        skeptic = ""
        if f.skeptic:
            alt = (f"<br><em>Alternative explanation:</em> {_e(f.skeptic.alternative_explanation)}"
                   if f.skeptic.alternative_explanation else "")
            skeptic = (f"<div class='skeptic'><strong>Skeptic review: {_e(f.skeptic.verdict)}"
                       f"</strong><br>{_e(f.skeptic.argument)}{alt}</div>")
        review = ""
        if f.reviewed_by:
            review = (f"<div class='meta'>Reviewed by {_e(f.reviewed_by)}"
                      f"{': ' + _e(f.review_note) if f.review_note else ''}</div>")
        cards.append(f"""
<section class="finding" id="{fid}">
  <div class="fhead">
    <span class="fid">{fid}</span>
    <span class="sev" style="background:{_SEV_COLOR.get(f.severity, '#475467')}">{_e(f.severity.upper())}</span>
    <span class="conf conf-{_e(f.confidence)}" title="{_e(_CONF_LABEL.get(f.confidence, ''))}">{_e(f.confidence)}</span>
    <span class="status"{f' title="{_e(f.approval_reason)}"' if f.approval_reason else ''}>{_e(f.status.replace('_', ' '))}</span>
    {tags}
  </div>
  <p class="claim">{_e(f.claim)}</p>
  {f'<p class="rationale">{_e(f.rationale)}</p>' if f.rationale else ''}
  {skeptic}{review}
  <details><summary>Evidence ({len(f.supporting_node_keys)} item{'s' if len(f.supporting_node_keys) != 1 else ''}) - author: {_e(f.author)}</summary>
  <table class="ev"><tr><th>Type</th><th>Item</th><th>Source record</th><th>Evidence file / SHA-256</th></tr>
  {_evidence_rows(session, f)}</table></details>
</section>""")

    custody = "".join(
        f"<tr><td>{_e(e['original_name'])}</td><td>{_e(e.get('format'))}</td>"
        f"<td>{_e(e['size_bytes'])}</td><td><code class='hash'>{_e(e['evidence_hash'])}</code></td>"
        f"<td>{_e(e['ingested_at'])}</td></tr>"
        for e in sorted(session.store.list_all(), key=lambda x: x.get("original_name") or ""))

    timeline_rows = []
    for item in session.graph.timeline(limit=400):
        if item["kind"] != "node" or item["node_type"] not in ("Alert", "AntivirusDetection"):
            continue
        n = item["node"]
        level = getattr(n, "level", None) or "high"
        timeline_rows.append(
            f"<tr><td>{_e(item['time'].strftime('%Y-%m-%d %H:%M:%S'))}</td>"
            f"<td>{_e(getattr(n, 'host_hostname', ''))}</td>"
            f"<td><span class='dot' style='background:{_SEV_COLOR.get({'informational': 'info'}.get(level, level), '#667085')}'></span>{_e(level)}</td>"
            f"<td>{_e(getattr(n, 'title', None) or getattr(n, 'threat_name', None) or getattr(n, 'event_description', ''))}</td></tr>")

    summary_md = summary_markdown or session.summary_markdown or ""
    # The page already has a "Summary" heading; drop a duplicate first heading.
    summary_md = re.sub(r"^\s*#{1,3}\s*(Summary|摘要)\s*\n", "", summary_md)
    summary_html = markdown_to_html(summary_md)
    stat = " ".join(f"<div class='stat'><b>{counts.get(s, 0)}</b><span>{s}</span></div>"
                    for s in ("critical", "high", "medium", "low", "info"))
    eval_html = (f"<h2>Accuracy against answer key</h2>{markdown_to_html(eval_markdown)}"
                 if eval_markdown else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GLAIVE report - {_e(session.case_name)}</title>
<style>
:root {{ --bg:#fff; --fg:#101828; --muted:#475467; --line:#e4e7ec; --card:#f9fafb; --accent:#1d4ed8; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0c111d; --fg:#f5f5f6; --muted:#a3a7ae; --line:#1f242f; --card:#131a29; --accent:#7aa2ff; }} }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans SC",sans-serif }}
main {{ max-width:1040px; margin:0 auto; padding:32px 16px 80px }}
h1 {{ font-size:26px; margin:0 0 4px }} h2 {{ font-size:19px; margin:36px 0 12px; border-bottom:1px solid var(--line); padding-bottom:6px }}
.sub {{ color:var(--muted) }} code {{ font-family:ui-monospace,Consolas,monospace; font-size:12.5px }}
.stats {{ display:flex; gap:10px; flex-wrap:wrap; margin:18px 0 }}
.stat {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:10px 16px; min-width:92px }}
.stat b {{ display:block; font-size:22px }} .stat span {{ color:var(--muted); text-transform:capitalize; font-size:13px }}
.finding {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px 16px; margin:12px 0 }}
.fhead {{ display:flex; gap:8px; align-items:center; flex-wrap:wrap }}
.fid {{ font-weight:700 }} .sev {{ color:#fff; border-radius:6px; padding:1px 8px; font-size:12px; font-weight:600 }}
.conf {{ border:1px solid var(--line); border-radius:6px; padding:1px 8px; font-size:12px }}
.conf-confirmed {{ border-color:#12b76a }} .conf-disputed {{ border-color:#f04438 }}
.status {{ color:var(--muted); font-size:12px }} .tag {{ font-size:11.5px; border-radius:5px; padding:1px 6px; background:rgba(29,78,216,.12); color:var(--accent) }}
.claim {{ font-size:16px; margin:10px 0 6px; overflow-wrap:anywhere }}
main li, main p {{ overflow-wrap:anywhere }} .rationale,.meta {{ color:var(--muted); margin:4px 0 }}
.skeptic {{ border-left:3px solid #f79009; padding:6px 10px; margin:8px 0; background:rgba(247,144,9,.07) }}
details summary {{ cursor:pointer; color:var(--accent); margin-top:6px }}
table {{ border-collapse:collapse; width:100%; font-size:13px; margin-top:8px }}
th,td {{ text-align:left; border-bottom:1px solid var(--line); padding:6px 8px; vertical-align:top; overflow-wrap:anywhere }}
.hash {{ font-size:11.5px; color:var(--muted) }} .dot {{ display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px }}
a.cite {{ color:var(--accent); text-decoration:none; font-weight:600 }}
.wrap {{ overflow-x:auto }}
footer {{ color:var(--muted); font-size:12.5px; margin-top:40px }}
</style></head><body><main>
<h1>{_e(session.case_name)}</h1>
<div class="sub">GLAIVE {__version__} investigation report - generated {now}</div>
<div class="stats">{stat}<div class="stat"><b>{len(session.store)}</b><span>evidence files</span></div></div>
<h2>Summary</h2>
{summary_html or '<p class="sub">No summary yet.</p>'}
<h2>Findings</h2>
<p class="sub">Every finding passed GLAIVE's verification gate: it cites real evidence, every name or
address it mentions appears in that evidence, and its confidence comes from the evidence, not the
author. Findings marked "pending approval" await an analyst's review.</p>
{''.join(cards) or '<p class="sub">No findings.</p>'}
<h2>Detection timeline</h2>
<div class="wrap"><table><tr><th>Time (UTC)</th><th>Host</th><th>Level</th><th>Detection</th></tr>{''.join(timeline_rows)}</table></div>
{eval_html}
<h2>Evidence and chain of custody</h2>
<div class="wrap"><table><tr><th>File</th><th>Format</th><th>Bytes</th><th>SHA-256</th><th>Ingested (UTC)</th></tr>{custody}</table></div>
<footer>Re-verify any file: compute its SHA-256 and compare with the table above (for example
<code>certutil -hashfile FILE SHA256</code> on Windows or <code>sha256sum FILE</code> on Linux).</footer>
</main></body></html>"""
