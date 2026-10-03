"""MITRE ATT&CK lookups: which tactics a technique belongs to.

    tactics_for("T1003.001")       -> ["TA0006"]          (Credential Access)
    tactic_id("defense_evasion")   -> "TA0005"
    tactic_name("TA0005")          -> "Stealth"

The table in attack.json was generated from the official Enterprise ATT&CK
STIX bundle (version in table()["version"]). ATT&CK v19 renamed Defense Evasion
(TA0005) to Stealth and split part of it into Defense Impairment (TA0112);
older names, Sigma tags ("attack.defense_evasion", "attack.defense-evasion")
and tactic IDs are all accepted. v19 also revoked techniques such as T1562.001
(now T1685); revoked IDs are kept, with the tactics of both the old and the new
technique, because rules and datasets still use them.

(c) The MITRE Corporation. Reproduced and distributed with the permission of
The MITRE Corporation.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

_TABLE_PATH = Path(__file__).parent / "attack.json"
_TID = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Names used before ATT&CK v19 (and by datasets labelled before then).
_ALIASES = {"defense-evasion": "TA0005", "defenseevasion": "TA0005"}
# A label of "Defense Evasion" also covers what v19 moved to Defense Impairment.
EQUIVALENT_TACTICS = {"TA0005": frozenset({"TA0005", "TA0112"}),
                      "TA0112": frozenset({"TA0005", "TA0112"})}


@lru_cache(maxsize=1)
def table() -> dict[str, Any]:
    return json.loads(_TABLE_PATH.read_text(encoding="utf-8"))


def _key(text: str) -> str:
    return re.sub(r"[\s_]+", "-", text.strip().lower())


@lru_cache(maxsize=256)
def tactic_id(name_or_tag: str) -> str | None:
    """'Credential Access', 'credential_access', 'attack.credential-access',
    'TA0006' -> 'TA0006'. None if it is not a tactic."""
    s = name_or_tag.strip()
    if s.lower().startswith("attack."):
        s = s[7:]
    if re.fullmatch(r"(?i)ta\d{4}", s):
        return s.upper() if s.upper() in table()["tactics"] else None
    k = _key(s)
    if k in _ALIASES:
        return _ALIASES[k]
    for tid, t in table()["tactics"].items():
        if k in (t["shortname"], _key(t["name"])):
            return tid
    return None


def tactic_name(tid: str) -> str:
    t = table()["tactics"].get(tid)
    return t["name"] if t else tid


def tactics_for(technique: str) -> list[str]:
    """Tactic IDs for a technique ID. Sub-techniques fall back to their parent
    when the table does not list them."""
    t = technique.strip().upper()
    if not _TID.match(t):
        return []
    techs = table()["techniques"]
    return list(techs.get(t) or techs.get(t.split(".")[0]) or [])


def tactics_from_tags(tags: list[str]) -> list[str]:
    """Tactic IDs named directly in Sigma tags (attack.execution ...)."""
    out: list[str] = []
    for tag in tags:
        low = tag.lower()
        if not low.startswith("attack.") or re.fullmatch(r"attack\.[tsg]\d{4}(\.\d{3})?", low):
            continue
        tid = tactic_id(tag)
        if tid and tid not in out:
            out.append(tid)
    return out


def tactics_of(techniques: list[str], tags: list[str] | None = None) -> list[str]:
    """All tactics implied by technique IDs plus those named in tags."""
    out = tactics_from_tags(tags or [])
    for t in techniques:
        for tid in tactics_for(t):
            if tid not in out:
                out.append(tid)
    return out


def current_id(technique: str) -> str:
    """The ID ATT&CK uses today: T1562.001 -> T1685 (revoked in v19)."""
    t = technique.strip().upper()
    seen = set()
    while t in table()["revoked_by"] and t not in seen:
        seen.add(t)
        t = table()["revoked_by"][t]
    return t


def same_tactic(a: str, b: str) -> bool:
    return a == b or b in EQUIVALENT_TACTICS.get(a, frozenset())


def same_technique(found: str, expected: str) -> bool:
    """T1003.006 matches an expected T1003 (and vice versa): the parent
    technique is what most labels and rules agree on. A revoked ID matches the
    technique that replaced it."""
    f, e = found.strip().upper(), expected.strip().upper()
    fs = {f, current_id(f)}
    es = {e, current_id(e)}
    return bool(fs & es) or bool({x.split(".")[0] for x in fs} & {x.split(".")[0] for x in es})
