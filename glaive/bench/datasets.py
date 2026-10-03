"""Public datasets GLAIVE is benchmarked on, and how their labels are read.

None of the data is bundled (licences and size); point each loader at a local
copy. Labels come from the dataset authors, never from GLAIVE:

  evtx-attack-samples  github.com/sbousseaden/EVTX-ATTACK-SAMPLES (GPL-3.0)
      One .evtx per attack, filed in a folder named after its ATT&CK tactic.
      Technique IDs are taken from file names when present (e.g. "_t1098").
  otrf                 github.com/OTRF/Security-Datasets (MIT)
      Atomic Windows datasets; each _metadata/*.yaml lists the ATT&CK
      techniques and tactics it simulates and links its host-log zip.
  benign               github.com/NextronSystems/evtx-baseline (Apache-2.0)
      Logs from clean Windows installs: every alert on it is a false alarm.
      Pass a release archive (e.g. win10-client.tgz), a folder of them, or
      a folder of extracted logs.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from glaive.detection.attack import tactic_id

_TECH_IN_NAME = re.compile(r"(?i)(?<![a-z0-9])t(\d{4})(?:[._](\d{3}))?(?![0-9])")
# Folders in EVTX-ATTACK-SAMPLES that are not an ATT&CK tactic.
_UNLABELLED = {"other", "automatedtestingtools", "evtx_att&ck_metadata"}


@dataclass
class BenchCase:
    id: str
    dataset: str
    paths: list[Path]
    tactics: list[str] = field(default_factory=list)      # expected, TA IDs
    techniques: list[str] = field(default_factory=list)   # expected, T IDs
    benign: bool = False
    title: str = ""


def _techniques_from_name(name: str) -> list[str]:
    out = []
    for m in _TECH_IN_NAME.finditer(name):
        t = f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
        if t not in out:
            out.append(t)
    return out


def evtx_attack_samples(root: Path) -> list[BenchCase]:
    root = Path(root)
    cases = []
    for f in sorted(root.rglob("*.evtx")):
        rel = f.relative_to(root)
        if len(rel.parts) < 2 or rel.parts[0].lower().replace(" ", "") in _UNLABELLED:
            continue
        tid = tactic_id(rel.parts[0])
        if tid is None:
            continue
        cases.append(BenchCase(id=str(rel.as_posix()), dataset="evtx-attack-samples",
                               paths=[f], tactics=[tid],
                               techniques=_techniques_from_name(f.stem), title=f.stem))
    return cases


def _otrf_local(root: Path, link: str) -> Path | None:
    marker = "/datasets/"
    if marker not in link:
        return None
    p = root / "datasets" / link.split(marker, 1)[1]
    return p if p.exists() else None


def otrf(root: Path) -> list[BenchCase]:
    """Windows atomic datasets of an OTRF Security-Datasets checkout."""
    root = Path(root)
    cases = []
    for meta in sorted((root / "datasets" / "atomic" / "_metadata").glob("*.yaml")):
        try:
            doc = yaml.safe_load(meta.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError):
            continue
        if "windows" not in [str(p).lower() for p in doc.get("platform") or []]:
            continue
        paths = [p for f in doc.get("files") or [] if str(f.get("type", "")).lower() == "host"
                 for p in [_otrf_local(root, str(f.get("link", "")))] if p]
        if not paths:
            continue
        techniques: list[str] = []
        tactics: list[str] = []
        for m in doc.get("attack_mappings") or []:
            t = str(m.get("technique") or "").upper()
            sub = m.get("sub-technique")
            if t:
                tech = f"{t}.{str(sub).zfill(3)}" if sub not in (None, "") else t
                if tech not in techniques:
                    techniques.append(tech)
            for ta in m.get("tactics") or []:
                tid = tactic_id(str(ta))
                if tid and tid not in tactics:
                    tactics.append(tid)
        if not techniques and not tactics:
            continue
        cases.append(BenchCase(id=str(doc.get("id") or meta.stem), dataset="otrf", paths=paths,
                               tactics=tactics, techniques=techniques,
                               title=str(doc.get("title") or "")))
    return cases


def benign(root: Path) -> list[BenchCase]:
    """One clean machine per release archive (win10-client.tgz ...) or per
    top-level folder of extracted logs; a folder of .evtx files directly is
    one machine."""
    from glaive.ingestion.pipeline import is_archive

    root = Path(root)
    if root.is_file():
        return [BenchCase(id=root.name, dataset="benign", paths=[root], benign=True,
                          title=root.name)] if is_archive(root) else []
    found = sorted(p for p in root.iterdir()
                   if (p.is_dir() and any(p.rglob("*.evtx"))) or (p.is_file() and is_archive(p)))
    if not found and any(root.glob("*.evtx")):
        found = [root]
    return [BenchCase(id=p.name, dataset="benign", paths=[p], benign=True, title=p.name)
            for p in found]


LOADERS = {"evtx-attack-samples": evtx_attack_samples, "otrf": otrf, "benign": benign}


def load(dataset: str, root: Path) -> list[BenchCase]:
    if dataset not in LOADERS:
        raise ValueError(f"Unknown dataset {dataset!r}. Choose from {sorted(LOADERS)}.")
    cases = LOADERS[dataset](Path(root))
    if not cases:
        raise ValueError(f"No {dataset} cases found under {root}. Is this the right folder?")
    return cases


def stratified(cases: list[BenchCase], limit: int | None) -> list[BenchCase]:
    """Up to `limit` cases, taken round-robin across expected tactics so a
    small sample still covers every tactic. Deterministic."""
    if not limit or limit >= len(cases):
        return list(cases)
    groups: dict[str, list[BenchCase]] = {}
    for c in cases:
        groups.setdefault(c.tactics[0] if c.tactics else "", []).append(c)
    out: list[BenchCase] = []
    iters: list[Iterator[BenchCase]] = [iter(v) for _, v in sorted(groups.items())]
    while len(out) < limit and iters:
        for it in list(iters):
            nxt = next(it, None)
            if nxt is None:
                iters.remove(it)
                continue
            out.append(nxt)
            if len(out) >= limit:
                break
    return out
