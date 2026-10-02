"""Router: retries, fallback, circuit breaker and token budget."""
from __future__ import annotations

import pytest

from glaive.llm.providers import ScriptedProvider
from glaive.llm.router import Router
from glaive.llm.types import BudgetExceeded, LLMError, Message


class Flaky(ScriptedProvider):
    def __init__(self, errors: list[LLMError], name: str = "flaky") -> None:
        super().__init__([Message("assistant", "ok")] * 10, name=name)
        self.errors = errors

    def complete(self, *a, **k):  # noqa: ANN002, ANN003
        if self.errors:
            raise self.errors.pop(0)
        return super().complete(*a, **k)


def test_router_retries_then_succeeds() -> None:
    p = Flaky([LLMError("429", retryable=True), LLMError("503", retryable=True)])
    r = Router([p], sleep=lambda s: None)
    assert r.complete([Message.user("x")]).message.content == "ok"
    assert r.stats["flaky"].failures == 2


def test_router_falls_back_on_hard_error() -> None:
    bad = Flaky([LLMError("401 bad key", retryable=False)] * 5, name="bad")
    good = ScriptedProvider([Message("assistant", "from backup")], name="good")
    r = Router([bad, good], sleep=lambda s: None)
    resp = r.complete([Message.user("x")])
    assert resp.provider == "good"
    assert r.stats["bad"].calls == 1  # no pointless retries on a bad key


def test_circuit_breaker_skips_dead_provider() -> None:
    dead = Flaky([LLMError("down", retryable=True)] * 50, name="dead")
    good = ScriptedProvider(lambda m, t: Message("assistant", "fine"), name="good")
    r = Router([dead, good], max_retries=0, breaker_threshold=2, sleep=lambda s: None)
    for _ in range(4):
        r.complete([Message.user("x")])
    assert r.stats["dead"].calls == 2  # opened after 2 failures, then skipped
    assert r.summary()["providers"]["dead"]["circuit_open"] is True


def test_token_budget() -> None:
    p = ScriptedProvider(lambda m, t: Message("assistant", "word " * 50))
    r = Router([p], token_budget=40)  # first call uses 1 + 50 tokens
    r.complete([Message.user("hello")])
    with pytest.raises(BudgetExceeded):
        r.complete([Message.user("hello")])


def test_all_providers_failing_raises() -> None:
    r = Router([Flaky([LLMError("x")] * 3)], sleep=lambda s: None)
    with pytest.raises(LLMError, match="All model providers failed"):
        r.complete([Message.user("x")])
