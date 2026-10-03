"""Integration: benchmark floors on the real public datasets.

These guard against regressions: if a change makes GLAIVE detect less on
data it was never built on, this fails. Point the variables at local copies,
then run: pytest -m integration tests/v03/test_bench_real.py

    GLAIVE_EVTX_SAMPLES  git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
    GLAIVE_OTRF          git clone https://github.com/OTRF/Security-Datasets
    GLAIVE_BASELINE      an extracted NextronSystems/evtx-baseline release
                         (e.g. win10-client.tgz)

The floors sit a little below the numbers in ACCURACY_REPORT.md.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from glaive.bench import load, run_benchmark


def _root(var: str) -> Path | None:
    v = os.environ.get(var)
    return Path(v) if v and Path(v).exists() else None


pytestmark = pytest.mark.integration


@pytest.mark.skipif(_root("GLAIVE_EVTX_SAMPLES") is None, reason="set GLAIVE_EVTX_SAMPLES")
def test_evtx_attack_samples_rules_only() -> None:
    res = run_benchmark(load("evtx-attack-samples", _root("GLAIVE_EVTX_SAMPLES")),
                        dataset="evtx-attack-samples")
    assert len(res.cases) == 261 and not [c for c in res.cases if c.error]
    hits, total = res.rate("alerts", "detected")
    assert hits / total >= 0.30


@pytest.mark.skipif(_root("GLAIVE_OTRF") is None, reason="set GLAIVE_OTRF")
def test_otrf_rules_only() -> None:
    res = run_benchmark(load("otrf", _root("GLAIVE_OTRF")), dataset="otrf")
    assert not [c for c in res.cases if c.error]
    hits, total = res.rate("findings", "tactic")
    assert hits / total >= 0.25


@pytest.mark.skipif(_root("GLAIVE_BASELINE") is None, reason="set GLAIVE_BASELINE")
def test_benign_baseline_false_alarms_stay_low() -> None:
    res = run_benchmark(load("benign", _root("GLAIVE_BASELINE")), dataset="benign")
    fa = res.false_alarms()
    assert fa["events"] > 100_000
    assert fa["alerts_per_10k_events"] <= 3.0 and fa["medium_or_higher"] <= 30
