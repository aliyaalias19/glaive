"""Model router: fallback, retries, circuit breaking, token budget, metrics.

    router = Router([claude, deepseek, local_qwen])
    reply = router.complete(messages, tools)

- Providers are tried in order. A retryable failure (rate limit, timeout,
  5xx) is retried with exponential backoff; a hard failure (bad key, unknown
  model) moves on to the next provider immediately.
- After `breaker_threshold` consecutive failures a provider's circuit opens
  and it is skipped for `breaker_cooldown` seconds, so one dead endpoint does
  not slow every call.
- `token_budget` caps total tokens for the investigation (cost control).
- Every call is recorded: per-provider calls, failures, tokens, latency.
- With `privacy` set, case data is pseudonymised before it is sent to a
  cloud provider and restored in the reply (see glaive.security.privacy).
  Local providers (Ollama, localhost, private network) get the real data.
"""
from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from glaive.llm.providers import Provider
from glaive.llm.types import BudgetExceeded, LLMError, LLMResponse, Message, ToolSpec
from glaive.observability import span
from glaive.security.privacy import Pseudonymizer, is_local_provider


@dataclass
class ProviderStats:
    calls: int = 0
    failures: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms_total: float = 0.0
    consecutive_failures: int = 0
    open_until: float = 0.0
    last_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        avg = self.latency_ms_total / self.calls if self.calls else 0.0
        return {"calls": self.calls, "failures": self.failures,
                "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "avg_latency_ms": round(avg, 1), "last_error": self.last_error,
                "circuit_open": self.open_until > time.monotonic()}


@dataclass
class Router:
    providers: list[Provider]
    max_retries: int = 2
    backoff_seconds: float = 1.0
    breaker_threshold: int = 3
    breaker_cooldown: float = 60.0
    token_budget: int | None = None
    on_event: Callable[[str, dict[str, Any]], None] | None = None
    sleep: Callable[[float], None] = time.sleep
    stats: dict[str, ProviderStats] = field(default_factory=dict)
    privacy: Pseudonymizer | None = None

    def __post_init__(self) -> None:
        if not self.providers:
            raise ValueError("Router needs at least one provider")
        for p in self.providers:
            self.stats.setdefault(p.name, ProviderStats())
        self._lock = threading.Lock()

    # ---- accounting -------------------------------------------------------------

    @property
    def tokens_used(self) -> int:
        return sum(s.input_tokens + s.output_tokens for s in self.stats.values())

    def describe(self) -> str:
        return " -> ".join(f"{p.name}:{p.model}" for p in self.providers)

    def summary(self) -> dict[str, Any]:
        out = {"chain": self.describe(), "tokens_used": self.tokens_used,
               "token_budget": self.token_budget,
               "providers": {n: s.to_dict() for n, s in self.stats.items()}}
        if self.privacy is not None:
            out["privacy"] = {"pseudonymized": self.privacy.summary(),
                              "replacements": self.privacy.replacements}
        return out

    def _emit(self, kind: str, **info: Any) -> None:
        if self.on_event:
            try:
                self.on_event(kind, info)
            except Exception:
                pass

    # ---- the call ---------------------------------------------------------------

    def complete(self, messages: list[Message], tools: list[ToolSpec] | None = None,
                 **kwargs: Any) -> LLMResponse:
        if self.token_budget is not None and self.tokens_used >= self.token_budget:
            raise BudgetExceeded(
                f"Token budget of {self.token_budget} reached ({self.tokens_used} used).")
        errors: list[str] = []
        now = time.monotonic()
        candidates = [p for p in self.providers if self.stats[p.name].open_until <= now]
        if not candidates:  # every circuit open: try the one that reopens soonest
            candidates = [min(self.providers, key=lambda p: self.stats[p.name].open_until)]
        for provider in candidates:
            st = self.stats[provider.name]
            masked = self.privacy is not None and not is_local_provider(provider)
            wire = self.privacy.mask_messages(messages) if masked and self.privacy else messages
            with span(f"chat {provider.model}", **{
                    "gen_ai.operation.name": "chat", "gen_ai.provider.name": provider.name,
                    "gen_ai.request.model": provider.model,
                    "gen_ai.request.max_tokens": kwargs.get("max_tokens"),
                    "glaive.request.messages": len(messages),
                    "glaive.request.tools": len(tools or []),
                    "glaive.privacy.pseudonymized": masked}) as sp:
                resp = self._try_provider(provider, st, wire, tools, masked, errors, sp, kwargs)
            if resp is not None:
                return resp
        raise LLMError("All model providers failed: " + " | ".join(errors[-6:]))

    def _try_provider(self, provider: Provider, st: ProviderStats, wire: list[Message],
                      tools: list[ToolSpec] | None, masked: bool, errors: list[str], sp: Any,
                      kwargs: dict[str, Any]) -> LLMResponse | None:
        """One provider, with retries. None means: move on to the next one."""
        for attempt in range(self.max_retries + 1):
            sp.set("glaive.attempts", attempt + 1)
            try:
                resp = provider.complete(wire, tools, **kwargs)
            except LLMError as e:
                with self._lock:
                    st.calls += 1
                    st.failures += 1
                    st.consecutive_failures += 1
                    st.last_error = str(e)[:200]
                    if st.consecutive_failures >= self.breaker_threshold:
                        st.open_until = time.monotonic() + self.breaker_cooldown
                errors.append(f"{provider.name}: {e}")
                self._emit("llm_error", provider=provider.name, error=str(e)[:200],
                           attempt=attempt, retryable=e.retryable)
                if e.retryable and attempt < self.max_retries and \
                        st.open_until <= time.monotonic():
                    delay = self.backoff_seconds * (2 ** attempt) * (0.5 + random.random())
                    self.sleep(delay)
                    continue
                sp.fail(e)
                return None  # next provider
            if masked and self.privacy:
                resp.message = self.privacy.unmask_message(resp.message)
            with self._lock:
                st.calls += 1
                st.consecutive_failures = 0
                st.open_until = 0.0
                st.input_tokens += resp.usage.input_tokens
                st.output_tokens += resp.usage.output_tokens
                st.latency_ms_total += resp.latency_ms
            self._emit("llm_call", provider=provider.name, model=resp.model,
                       input_tokens=resp.usage.input_tokens,
                       output_tokens=resp.usage.output_tokens,
                       latency_ms=round(resp.latency_ms, 1),
                       fallback=provider is not self.providers[0], pseudonymized=masked)
            sp.set("gen_ai.response.model", resp.model)
            sp.set("gen_ai.usage.input_tokens", resp.usage.input_tokens)
            sp.set("gen_ai.usage.output_tokens", resp.usage.output_tokens)
            sp.set("gen_ai.response.finish_reasons", [resp.finish_reason or "unknown"])
            sp.set("glaive.response.tool_calls", len(resp.message.tool_calls))
            return resp
        return None
