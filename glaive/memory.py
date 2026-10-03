"""Past-case memory: what you saw in earlier investigations, searchable later.

    glaive remember ./case-2026-09        add a finished case's findings
    glaive memory search "comsvcs"        search everything remembered
    glaive memory forget "Case name"      remove a case

Memory is opt-in and local: nothing is remembered until you run
`glaive remember`, and it is stored on this computer only, in
GLAIVE_HOME/memory.sqlite (default ~/.glaive). GLAIVE_MEMORY=off disables it.

What is kept per finding: the claim, severity, confidence, ATT&CK techniques,
the case name and date, and its indicators (hashes, public IP addresses,
domains, threat names, unusual file paths). When a new case shares an
indicator with a remembered one, GLAIVE says so ("203.0.113.47 was also seen
in Operation Invoice"), and agents can search memory with the
recall_past_cases tool.

A remembered finding is context, not evidence: it can explain where to look,
but a new finding must still cite this case's own evidence to pass the gate.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from glaive.reporting.grounding import extract_entities
from glaive.security.privacy import is_internal_ip

_IOC_KINDS = {"sha256", "sha1", "md5", "ip", "domain", "threat_name", "windows_path"}
# Normalised paths use forward slashes and lower case.
_COMMON_PATH_PREFIXES = ("c:/windows/system32/", "c:/windows/syswow64/", "c:/program files",
                         "c:/windows/winsxs/")


def memory_path(env: Mapping[str, str] | None = None) -> Path | None:
    """Where memory lives, or None when GLAIVE_MEMORY=off."""
    env = os.environ if env is None else env
    if (env.get("GLAIVE_MEMORY") or "").strip().lower() in ("off", "0", "false", "no"):
        return None
    home = env.get("GLAIVE_HOME") or str(Path.home() / ".glaive")
    return Path(home) / "memory.sqlite"


def indicators(text: str) -> list[str]:
    """Indicators worth matching across cases ('kind:value', normalised)."""
    out: list[str] = []
    for e in extract_entities(text):
        if e.kind not in _IOC_KINDS:
            continue
        v = e.normalized()
        if e.kind == "ip" and (is_internal_ip(v) or v.startswith("127.")):
            continue  # internal addresses repeat across unrelated clients
        if e.kind == "windows_path" and v.lower().startswith(_COMMON_PATH_PREFIXES):
            continue
        item = f"{e.kind}:{v}"
        if item not in out:
            out.append(item)
    return out


@dataclass
class Remembered:
    case_name: str
    finding_id: str
    claim: str
    severity: str
    confidence: str
    mitre: list[str]
    committed_at: str
    indicators: list[str]

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class Memory:
    """The local store of remembered findings."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY, case_name TEXT, case_path TEXT, claim TEXT,
                severity TEXT, confidence TEXT, mitre TEXT, committed_at TEXT,
                indicators TEXT, remembered_at TEXT);
            CREATE TABLE IF NOT EXISTS iocs (indicator TEXT, finding_id TEXT,
                PRIMARY KEY (indicator, finding_id));
            CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
                claim, case_name, content='findings', content_rowid='rowid');
        """)

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> Memory:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- writing --------------------------------------------------------------------

    def remember(self, session: Any) -> int:
        """Add a case's committed findings (analyst-rejected ones are skipped).
        Re-running it updates the case. Returns how many findings were stored."""
        rows = [f for f in session.report.findings if f.status != "rejected_by_analyst"]
        now = datetime.now(UTC).isoformat(timespec="seconds")
        with self._lock, self._db:
            self._forget(session.case_name)
            for f in rows:
                iocs = indicators(f.claim)
                self._db.execute(
                    "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (f.finding_id, session.case_name, str(session.analysis_dir.resolve()),
                     f.claim, f.severity, f.confidence, json.dumps(f.mitre_techniques),
                     f.committed_at.isoformat(), json.dumps(iocs), now))
                self._db.executemany("INSERT OR IGNORE INTO iocs VALUES (?, ?)",
                                     [(i, f.finding_id) for i in iocs])
            self._db.execute("INSERT INTO findings_fts(findings_fts) VALUES('rebuild')")
        return len(rows)

    def _forget(self, case_name: str) -> int:
        ids = [r[0] for r in self._db.execute(
            "SELECT finding_id FROM findings WHERE case_name = ?", (case_name,))]
        self._db.executemany("DELETE FROM iocs WHERE finding_id = ?", [(i,) for i in ids])
        self._db.execute("DELETE FROM findings WHERE case_name = ?", (case_name,))
        return len(ids)

    def forget(self, case_name: str) -> int:
        with self._lock, self._db:
            n = self._forget(case_name)
            self._db.execute("INSERT INTO findings_fts(findings_fts) VALUES('rebuild')")
        return n

    # ---- reading --------------------------------------------------------------------

    def _row(self, r: tuple) -> Remembered:
        return Remembered(case_name=r[0], finding_id=r[1], claim=r[2], severity=r[3],
                          confidence=r[4], mitre=json.loads(r[5] or "[]"), committed_at=r[6],
                          indicators=json.loads(r[7] or "[]"))

    _COLS = "case_name, finding_id, claim, severity, confidence, mitre, committed_at, indicators"

    def cases(self) -> list[dict[str, Any]]:
        return [{"case_name": c, "findings": n, "remembered_at": t} for c, n, t in self._db.execute(
            "SELECT case_name, COUNT(*), MAX(remembered_at) FROM findings GROUP BY case_name "
            "ORDER BY MAX(remembered_at) DESC")]

    def search(self, query: str, limit: int = 10,
               exclude_case: str | None = None) -> list[Remembered]:
        from glaive.retrieval.index import fts_query

        q = fts_query(query)
        if q is None:
            return []
        sql = (f"SELECT {', '.join('f.' + c.strip() for c in self._COLS.split(','))} "
               "FROM findings_fts JOIN findings f ON f.rowid = findings_fts.rowid "
               "WHERE findings_fts MATCH ? AND (? IS NULL OR f.case_name != ?) "
               "ORDER BY bm25(findings_fts) LIMIT ?")
        return [self._row(r) for r in self._db.execute(sql, (q, exclude_case, exclude_case,
                                                             limit))]

    def overlaps(self, session: Any) -> list[dict[str, Any]]:
        """Indicators of this case's findings that earlier cases also had."""
        out: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for f in session.report.findings:
            for ioc in indicators(f.claim):
                for r in self._db.execute(
                        f"SELECT {self._COLS} FROM findings WHERE case_name != ? AND "
                        "finding_id IN (SELECT finding_id FROM iocs WHERE indicator = ?)",
                        (session.case_name, ioc)):
                    past = self._row(r)
                    if (ioc, past.case_name) in seen:
                        continue
                    seen.add((ioc, past.case_name))
                    out.append({"indicator": ioc, "finding": f.short_id,
                                "past_case": past.case_name, "past_claim": past.claim,
                                "past_date": past.committed_at[:10]})
        return out


def open_memory(env: Mapping[str, str] | None = None, create: bool = False) -> Memory | None:
    """The memory store, or None if it is disabled or (unless create) empty."""
    path = memory_path(env)
    if path is None or (not create and not path.exists()):
        return None
    return Memory(path)
