"""Correlation detections: patterns that only appear across several events.

These complement Sigma (which looks at one event at a time). Each function
takes the time-sorted event list (and, where useful, the single-event
alerts) and returns CorrelationHit objects anchored to a real event, so the
resulting alert has normal provenance.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from glaive.ingestion.windows import classify_channel, parse_time
from glaive.security.injection import scan_text


@dataclass
class CorrelationHit:
    rule_id: str
    title: str
    level: str
    description: str
    mitre: list[str]
    anchor: dict[str, Any]          # the event the alert is attached to
    related_uids: list[str] = field(default_factory=list)
    matched: dict[str, str] = field(default_factory=dict)


def brute_force_then_success(events: list[dict], threshold: int = 5,
                             window: timedelta = timedelta(minutes=10),
                             success_within: timedelta = timedelta(minutes=30)
                             ) -> list[CorrelationHit]:
    """>= `threshold` failed logons from one source within `window`, then a
    successful logon from the same source shortly after."""
    fails: dict[tuple[str, str], list[dict]] = defaultdict(list)
    hits: list[CorrelationHit] = []
    reported: set[tuple[str, str]] = set()
    for ev in events:
        if classify_channel(ev) != "security" or ev.get("event_id") not in (4624, 4625):
            continue
        d = ev.get("raw_data") or {}
        src = d.get("IpAddress") or d.get("WorkstationName") or ""
        if src in ("", "-", "::1", "127.0.0.1"):
            continue
        key = (ev["computer"], src)
        t = parse_time(ev["time_created"])
        if t is None:
            continue
        if ev["event_id"] == 4625:
            fails[key].append(ev)
            continue
        if key in reported:
            continue
        recent = [f for f in fails[key]
                  if (pt := parse_time(f["time_created"])) and t - success_within <= pt <= t]
        if len(recent) < threshold:
            continue
        first = parse_time(recent[0]["time_created"])
        last = parse_time(recent[-1]["time_created"])
        if first and last and last - first <= window + success_within:
            reported.add(key)
            users = sorted({(f.get("raw_data") or {}).get("TargetUserName", "?") for f in recent})
            hits.append(CorrelationHit(
                rule_id="glaive.correlation.brute_force_success",
                title="Brute Force Followed by Successful Logon",
                level="critical",
                description=(f"{len(recent)} failed logons from {src} to {ev['computer']} "
                             f"(accounts tried: {', '.join(users[:5])}) followed by a successful "
                             f"logon as {d.get('TargetUserName')}."),
                mitre=["T1110", "T1078"],
                anchor=ev,
                related_uids=[f["_uid"] for f in recent if f.get("_uid")],
                matched={"IpAddress": src, "TargetUserName": d.get("TargetUserName", ""),
                         "FailedAttempts": str(len(recent))}))
    return hits


_TAMPER_RULE_HINTS = ("defender", "exclusion")


def tamper_then_malicious(events: list[dict], alerts: list[dict],
                          within: timedelta = timedelta(hours=2)) -> list[CorrelationHit]:
    """Security tooling was disabled on a host, then a high/critical alert
    fired on the same host soon after."""
    tamper_by_host: dict[str, list[tuple[Any, dict]]] = defaultdict(list)
    for ev in events:
        if classify_channel(ev) == "defender" and ev.get("event_id") in (5001, 5010, 5012):
            t = parse_time(ev["time_created"])
            if t:
                tamper_by_host[ev["computer"]].append((t, ev))
    for a in alerts:
        if any(h in a["title"].lower() for h in _TAMPER_RULE_HINTS) and \
                "disabled" in a["title"].lower() + a.get("description", "").lower():
            tamper_by_host[a["host"]].append((a["time"], a["event"]))
    hits: list[CorrelationHit] = []
    seen: set[tuple[str, str]] = set()
    for a in alerts:
        if a["level"] not in ("high", "critical") or "defender" in a["title"].lower():
            continue
        for t_time, t_ev in tamper_by_host.get(a["host"], []):
            if t_time <= a["time"] <= t_time + within:
                k = (a["host"], a["rule_id"])
                if k in seen:
                    continue
                seen.add(k)
                hits.append(CorrelationHit(
                    rule_id="glaive.correlation.tamper_then_malicious",
                    title="Security Tooling Disabled Before Malicious Activity",
                    level="critical",
                    description=(f"Protection was disabled on {a['host']} at "
                                 f"{t_time.isoformat()} and '{a['title']}' followed at "
                                 f"{a['time'].isoformat()}."),
                    mitre=["T1562.001"],
                    anchor=a["event"],
                    related_uids=[u for u in (t_ev.get("_uid"),) if u],
                    matched={"FollowedBy": a["title"]}))
                break
    return hits


# Fields where attacker-controlled free text appears.
_TEXT_FIELDS = ("CommandLine", "ParentCommandLine", "ScriptBlockText", "TaskContent",
                "ImagePath", "Details", "QueryName", "TargetFilename", "Description",
                "ServiceName", "Threat Name", "Payload")


def prompt_injection_in_evidence(events: list[dict]) -> list[CorrelationHit]:
    """Text aimed at AI investigators, planted inside evidence."""
    hits: list[CorrelationHit] = []
    for ev in events:
        d = ev.get("raw_data") or {}
        for f in _TEXT_FIELDS:
            found = scan_text(d.get(f))
            if found:
                hits.append(CorrelationHit(
                    rule_id="glaive.prompt_injection_in_evidence",
                    title="Prompt-Injection Text Planted in Evidence",
                    level="high",
                    description=("Evidence contains text that tries to instruct an AI "
                                 f"investigator ({', '.join(h.pattern for h in found)}). GLAIVE "
                                 "treats it as data only. Its presence suggests an attacker "
                                 "anticipating AI-assisted analysis."),
                    mitre=["T1036"],
                    anchor=ev,
                    matched={f: found[0].excerpt}))
                break
    return hits
