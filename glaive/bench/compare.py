"""Put saved benchmark runs side by side (rules alone vs each model).

    glaive bench compare bench-results/*.json
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_results(paths: list[Path]) -> list[dict[str, Any]]:
    out = []
    for p in paths:
        data = json.loads(Path(p).read_text(encoding="utf-8"))
        if "dataset" in data and "mode" in data:
            data["_file"] = Path(p).name
            out.append(data)
    return out


def _pct(block: dict[str, int] | None) -> str:
    if not block or not block.get("total"):
        return "-"
    return f"{block['hits'] / block['total']:.0%}"


def compare_markdown(runs: list[dict[str, Any]]) -> str:
    """One row per run: the same dataset scored by rules alone and by each
    model. Columns are findings-level (what the investigation committed)."""
    runs = sorted(runs, key=lambda r: (r["dataset"], r["mode"] != "rules", r.get("model") or ""))
    lines = ["| Dataset | Run | Rules | Cases | Flagged | Right tactic | Right technique "
             "| False alarms (benign) | Tokens | Time |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in runs:
        s = (r.get("summary") or {}).get("findings") or {}
        fa = r.get("false_alarms")
        fa_txt = f"{fa['alerts']} alerts, {fa['findings']} findings" if fa else "-"
        who = "rules only" if r["mode"] == "rules" else (r.get("model") or "ai")
        lines.append(f"| {r['dataset']} | {who} | {r.get('rules', '')} | {r.get('cases_total')} "
                     f"| {_pct(s.get('detected'))} | {_pct(s.get('tactic'))} "
                     f"| {_pct(s.get('technique'))} | {fa_txt} | {r.get('tokens', 0):,} "
                     f"| {r.get('seconds', 0):.0f}s |")
    return "\n".join(lines) + "\n"
