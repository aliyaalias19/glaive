"""Claim grounding: the check v0.1's gate was missing.

v0.1 verified that every supporting node EXISTS, but never compared the
claim TEXT with those nodes. An agent could cite a real AV detection and claim
"Domain admin credentials were exfiltrated to 8.8.8.8" and the gate accepted
it. That is precisely the hallucination GLAIVE exists to stop.

This module extracts the concrete, checkable entities a forensic claim makes
(IPs, hashes, paths, executables, threat names, SIDs, PIDs, domains, ports)
and requires each one to appear in the evidence neighbourhood of the cited
nodes (the nodes themselves + 1-hop neighbours + connecting edges).

It is deliberately deterministic: no LLM decides whether a claim is grounded.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from glaive.graph.wrapper import EvidenceGraph

# Order matters: more specific patterns first; matched spans are masked so
# that e.g. an IP inside a URL is not double-extracted.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("sid", re.compile(r"\bS-1-\d+(?:-\d+){1,14}\b")),
    ("threat_name", re.compile(r"\b[A-Za-z]+:[A-Za-z0-9]+/[\w.!-]+")),
    ("windows_path", re.compile(r"(?:[A-Za-z]:|\\\\[\w.$-]+)\\[^\s\"'<>|,;]+")),
    ("ip", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("executable", re.compile(
        r"\b[\w.-]+\.(?:exe|dll|sys|ps1|psm1|bat|cmd|vbs|js|jse|scr|lnk|hta|msi|jar|py|sh|zip|rar|7z|iso)\b",
        re.IGNORECASE,
    )),
    ("domain", re.compile(
        r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|tk|onion|co|me|app|dev)\b",
        re.IGNORECASE,
    )),
    ("pid", re.compile(r"\b(?:pid|process id)\s*[:#=]?\s*(\d{1,7})\b", re.IGNORECASE)),
    ("port", re.compile(r"\bport\s*[:#=]?\s*(\d{1,5})\b", re.IGNORECASE)),
]


@dataclass
class Entity:
    kind: str
    value: str

    def normalized(self) -> str:
        return _norm(self.value)


@dataclass
class GroundingResult:
    entities: list[Entity] = field(default_factory=list)
    grounded: list[Entity] = field(default_factory=list)
    ungrounded: list[Entity] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.ungrounded

    @property
    def coverage(self) -> float:
        """Fraction of extracted entities found in evidence (1.0 if none)."""
        if not self.entities:
            return 1.0
        return len(self.grounded) / len(self.entities)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities_checked": len(self.entities),
            "coverage": round(self.coverage, 3),
            "grounded": [f"{e.kind}:{e.value}" for e in self.grounded],
            "ungrounded": [f"{e.kind}:{e.value}" for e in self.ungrounded],
        }


def _norm(s: str) -> str:
    s = s.strip().strip(".").lower().replace("\\", "/")
    if s.startswith("/??/"):
        s = s[4:]
    return s


def extract_entities(text: str) -> list[Entity]:
    """Extract checkable forensic entities from free text."""
    found: list[Entity] = []
    seen: set[tuple[str, str]] = set()
    masked = text
    for kind, pat in _PATTERNS:
        for m in pat.finditer(masked):
            value = m.group(1) if pat.groups else m.group(0)
            # Sentence punctuation is not part of a path/name: "...Pipe)." -> "...Pipe"
            value = value.rstrip(".,;:)]}'\"")
            k = (kind, _norm(value))
            if k not in seen:
                seen.add(k)
                found.append(Entity(kind, value))
        masked = pat.sub(lambda m: " " * len(m.group(0)), masked)
    return found


def _flatten(value: Any, out: list[str]) -> None:
    if value is None:
        return
    if isinstance(value, datetime):
        out.append(value.isoformat())
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            _flatten(v, out)
    elif isinstance(value, dict):
        for k, v in value.items():
            _flatten(k, out)
            _flatten(v, out)
    elif isinstance(value, bytes):
        out.append(value.decode("utf-8", "replace"))
    else:
        out.append(str(value))


def evidence_haystack(graph: EvidenceGraph, keys: list[tuple], hops: int = 1) -> str:
    """All attribute text in the cited nodes' k-hop neighbourhood, normalized."""
    neighbourhood: set[tuple] = set()
    for k in keys:
        neighbourhood |= graph.neighbors(tuple(k), depth=hops, max_nodes=500)
    nodes, edges = graph.subgraph(neighbourhood)
    parts: list[str] = []
    for n in nodes:
        _flatten(n.model_dump(exclude={"evidence_hash", "derivation", "observed_at"}), parts)
    for e in edges:
        _flatten(e.model_dump(exclude={"evidence_hash", "derivation", "observed_at",
                                       "source_key", "target_key"}), parts)
    return "\n".join(_norm(p) for p in parts)


def check_grounding(
    claim: str, graph: EvidenceGraph, keys: list[tuple], hops: int = 1
) -> GroundingResult:
    """Check every entity in `claim` against the cited evidence neighbourhood."""
    result = GroundingResult(entities=extract_entities(claim))
    if not result.entities:
        return result
    hay = evidence_haystack(graph, keys, hops=hops)
    for ent in result.entities:
        needle = ent.normalized()
        if ent.kind in ("pid", "port"):
            hit = re.search(rf"(?<![\d]){re.escape(needle)}(?![\d])", hay) is not None
        else:
            hit = needle in hay
        (result.grounded if hit else result.ungrounded).append(ent)
    return result
