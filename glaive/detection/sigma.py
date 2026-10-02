"""A small, dependency-free Sigma rule engine.

Sigma (https://github.com/SigmaHQ/sigma) is the community standard format for
log detection rules. GLAIVE evaluates Sigma rules directly against parsed
Windows events, so detections work with no AI model and no SIEM.

Supported:
  - logsource: product windows; services security / system / sysmon /
    powershell / windefend; categories process_creation, network_connection,
    file_event, registry_event / registry_set / registry_add, dns_query,
    ps_script
  - detection: maps (AND of fields), lists of maps (OR), keyword lists,
    value lists (OR), null values
  - modifiers: contains, startswith, endswith, all, re, cidr, windash,
    exists, gt, gte, lt, lte
  - wildcards * and ? in values (case-insensitive, as Sigma specifies)
  - conditions: and, or, not, parentheses, "1 of x*", "all of x*",
    "1 of them", "all of them"

Not supported (rules using them are skipped and reported, never mis-evaluated):
  aggregation conditions ("| count() > 5"), base64 / base64offset / utf16
  modifiers, near, correlation rules.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from glaive.ingestion.windows import classify_channel

logger = logging.getLogger(__name__)

Matcher = Callable[[dict[str, str]], bool]

LEVELS = ["informational", "low", "medium", "high", "critical"]


class UnsupportedRule(Exception):
    """The rule uses a Sigma feature this engine does not implement."""


# ---- event view ------------------------------------------------------------------

# Security 4688 uses different field names from Sysmon 1 for the same facts.
# Sigma process_creation rules are written against the Sysmon names.
_ALIASES_4688 = {
    "Image": "NewProcessName",
    "ParentImage": "ParentProcessName",
    "User": "SubjectUserName",
    "ProcessId": "NewProcessId",
    "ParentProcessId": "ProcessId",
}


def event_view(ev: dict[str, Any]) -> dict[str, str]:
    """Flatten an event into the field namespace Sigma rules use.
    Keys are lower-cased for case-insensitive field lookup."""
    raw = ev.get("raw_data") or {}
    view = {k.lower(): ("" if v is None else str(v)) for k, v in raw.items()}
    view["eventid"] = str(ev.get("event_id", ""))
    view["channel"] = ev.get("channel") or ""
    view["provider_name"] = ev.get("provider") or ""
    view["computer"] = ev.get("computer") or ""
    if ev.get("event_id") == 4688 and classify_channel(ev) == "security":
        for sigma_name, sec_name in _ALIASES_4688.items():
            if sec_name.lower() in view:
                view.setdefault(sigma_name.lower(), view[sec_name.lower()])
        # Sigma's ProcessId means the NEW process; 4688's ProcessId is the parent.
        if "newprocessid" in view:
            view["parentprocessid"] = view.get("processid", "")
            view["processid"] = view["newprocessid"]
    return view


# ---- logsource -------------------------------------------------------------------

_SERVICE_FAMILY = {
    "security": "security", "system": "system", "sysmon": "sysmon",
    "powershell": "powershell", "windefend": "defender",
}

_CATEGORY = {
    "process_creation": {("sysmon", 1), ("security", 4688)},
    "network_connection": {("sysmon", 3)},
    "file_event": {("sysmon", 11)},
    "registry_event": {("sysmon", 12), ("sysmon", 13), ("sysmon", 14)},
    "registry_set": {("sysmon", 13)},
    "registry_add": {("sysmon", 12)},
    "dns_query": {("sysmon", 22)},
    "ps_script": {("powershell", 4104)},
    "process_access": {("sysmon", 10)},
    "image_load": {("sysmon", 7)},
}


def _logsource_filter(ls: dict[str, Any]) -> Callable[[str, int], bool]:
    product = (ls.get("product") or "windows").lower()
    if product != "windows":
        raise UnsupportedRule(f"product {product!r}")
    service = (ls.get("service") or "").lower()
    category = (ls.get("category") or "").lower()
    if service and service not in _SERVICE_FAMILY:
        raise UnsupportedRule(f"service {service!r}")
    if category and category not in _CATEGORY:
        raise UnsupportedRule(f"category {category!r}")
    fam = _SERVICE_FAMILY.get(service)
    allowed = _CATEGORY.get(category)

    def ok(family: str, event_id: int) -> bool:
        if fam and family != fam:
            return False
        if allowed and (family, event_id) not in allowed:
            return False
        return True

    return ok


# ---- value matching -----------------------------------------------------------------


def _wildcard_body(value: str) -> str:
    """Sigma value -> regex body. '*' and '?' are wildcards; a backslash
    escapes only '*', '?' or another backslash and is literal otherwise."""
    out = []
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def _wildcard_regex(value: str, prefix: str = "", suffix: str = "") -> re.Pattern[str]:
    """Compile a Sigma value. Modifier wildcards (prefix/suffix) are added AFTER
    escape processing, so contains:'\\' means 'contains a backslash'."""
    return re.compile("^" + prefix + _wildcard_body(value) + suffix + "$",
                      re.IGNORECASE | re.DOTALL)


def _windash(value: str) -> list[str]:
    variants = {value}
    for dash in ("-", "/", "–", "—", "―"):
        variants.add(re.sub(r"(^|\s)-", lambda m, d=dash: m.group(1) + d, value))
    return sorted(variants)


def _value_matcher(raw: Any, mods: list[str]) -> Callable[[str | None], bool]:
    """Matcher for ONE expected value under the given modifiers."""
    if raw is None:
        return lambda actual: actual is None or actual == ""

    if "exists" in mods:
        want = bool(raw)
        return lambda actual: (actual is not None) == want

    for numeric in ("gt", "gte", "lt", "lte"):
        if numeric in mods:
            limit = float(raw)

            def num(actual: str | None, op: str = numeric, limit: float = limit) -> bool:
                try:
                    a = float(actual or "")
                except ValueError:
                    return False
                return {"gt": a > limit, "gte": a >= limit, "lt": a < limit,
                        "lte": a <= limit}[op]
            return num

    if "cidr" in mods:
        net = ipaddress.ip_network(str(raw), strict=False)

        def in_net(actual: str | None) -> bool:
            try:
                return actual is not None and ipaddress.ip_address(actual) in net
            except ValueError:
                return False
        return in_net

    if "re" in mods:
        flags = re.IGNORECASE if "i" in mods else 0
        pat = re.compile(str(raw), flags)
        return lambda actual: actual is not None and pat.search(actual) is not None

    value = str(raw).lower() if isinstance(raw, bool) else str(raw)
    candidates = _windash(value) if "windash" in mods else [value]
    pre = ".*" if ("contains" in mods or "endswith" in mods) else ""
    post = ".*" if ("contains" in mods or "startswith" in mods) else ""
    pats = [_wildcard_regex(v, pre, post) for v in candidates]
    return lambda actual: actual is not None and any(p.match(actual) for p in pats)


_KNOWN_MODS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cidr",
               "windash", "exists", "gt", "gte", "lt", "lte"}


def _field_matcher(spec: str, expected: Any) -> Matcher:
    name, *mods = spec.split("|")
    mods = [m.lower() for m in mods]
    unknown = set(mods) - _KNOWN_MODS
    if unknown:
        raise UnsupportedRule(f"modifier(s) {sorted(unknown)}")
    field_name = name.lower()
    values = expected if isinstance(expected, list) else [expected]
    if not values:
        raise UnsupportedRule(f"empty value list for {spec}")
    checks = [_value_matcher(v, mods) for v in values]
    combine = all if "all" in mods else any

    def match(view: dict[str, str]) -> bool:
        actual = view.get(field_name)
        return combine(c(actual) for c in checks)

    return match


def _keyword_matcher(words: list[Any]) -> Matcher:
    pats = [_wildcard_regex(str(w), ".*", ".*") for w in words]

    def match(view: dict[str, str]) -> bool:
        return any(p.match(v) for v in view.values() for p in pats)

    return match


def _search_matcher(definition: Any) -> Matcher:
    if isinstance(definition, dict):
        parts = [_field_matcher(k, v) for k, v in definition.items()]
        return lambda view: all(p(view) for p in parts)
    if isinstance(definition, list):
        if all(isinstance(x, dict) for x in definition):
            alts = [_search_matcher(x) for x in definition]
            return lambda view: any(a(view) for a in alts)
        if all(not isinstance(x, (dict, list)) for x in definition):
            return _keyword_matcher(definition)
    if isinstance(definition, (str, int)):
        return _keyword_matcher([definition])
    raise UnsupportedRule("unrecognised detection item")


# ---- condition parsing --------------------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


def _compile_condition(cond: str, searches: dict[str, Matcher]) -> Matcher:
    if "|" in cond:
        raise UnsupportedRule("aggregation conditions")
    tokens = [t for t in _TOKEN.findall(cond) if t]
    pos = 0

    def peek() -> str | None:
        return tokens[pos].lower() if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def names_for(pattern: str) -> list[Matcher]:
        if pattern.lower() == "them":
            chosen = [m for n, m in searches.items() if not n.startswith("_")]
        else:
            rx = _wildcard_regex(pattern)
            chosen = [m for n, m in searches.items() if rx.match(n)]
        if not chosen:
            raise UnsupportedRule(f"condition references unknown {pattern!r}")
        return chosen

    def primary() -> Matcher:
        tok = peek()
        if tok is None:
            raise UnsupportedRule("truncated condition")
        if tok == "(":
            take()
            inner = expr()
            if peek() != ")":
                raise UnsupportedRule("unbalanced parentheses")
            take()
            return inner
        if tok == "not":
            take()
            inner = primary()
            return lambda v: not inner(v)
        if tok in ("1", "any", "all") and pos + 1 < len(tokens) and tokens[pos + 1].lower() == "of":
            quant = take().lower()
            take()  # 'of'
            group = names_for(take())
            if quant == "all":
                return lambda v: all(m(v) for m in group)
            return lambda v: any(m(v) for m in group)
        name = take()
        if name not in searches:
            raise UnsupportedRule(f"condition references unknown {name!r}")
        m = searches[name]
        return m

    def conj() -> Matcher:
        left = primary()
        while peek() == "and":
            take()
            right = primary()
            left = (lambda a, b: lambda v: a(v) and b(v))(left, right)
        return left

    def expr() -> Matcher:
        left = conj()
        while peek() == "or":
            take()
            right = conj()
            left = (lambda a, b: lambda v: a(v) or b(v))(left, right)
        return left

    result = expr()
    if pos != len(tokens):
        raise UnsupportedRule(f"unexpected token {tokens[pos]!r}")
    return result


# ---- rules -------------------------------------------------------------------------


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    description: str
    tags: list[str]
    logsource: dict[str, Any]
    falsepositives: list[str] = field(default_factory=list)
    path: str = ""
    _accepts: Callable[[str, int], bool] = field(default=lambda f, e: True, repr=False)
    _match: Matcher = field(default=lambda v: False, repr=False)

    @property
    def mitre_techniques(self) -> list[str]:
        out = []
        for t in self.tags:
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", t.lower())
            if m:
                out.append(m.group(1).upper())
        return out

    def matches(self, family: str, event_id: int, view: dict[str, str]) -> bool:
        return self._accepts(family, event_id) and self._match(view)


def compile_rule(doc: dict[str, Any], path: str = "") -> SigmaRule:
    if not isinstance(doc, dict) or "detection" not in doc:
        raise UnsupportedRule("not a detection rule")
    detection = dict(doc["detection"])
    condition = detection.pop("condition", None)
    if isinstance(condition, list):
        if len(condition) != 1:
            raise UnsupportedRule("multiple conditions")
        condition = condition[0]
    if not condition:
        raise UnsupportedRule("missing condition")
    detection.pop("timeframe", None)
    searches = {name: _search_matcher(defn) for name, defn in detection.items()}
    level = str(doc.get("level") or "medium").lower()
    return SigmaRule(
        id=str(doc.get("id") or doc.get("title")),
        title=str(doc.get("title") or "Untitled rule"),
        level=level if level in LEVELS else "medium",
        description=str(doc.get("description") or "").strip(),
        tags=[str(t) for t in doc.get("tags") or []],
        logsource=dict(doc.get("logsource") or {}),
        falsepositives=[str(x) for x in doc.get("falsepositives") or []],
        path=path,
        _accepts=_logsource_filter(dict(doc.get("logsource") or {})),
        _match=_compile_condition(str(condition), searches),
    )


BUILTIN_RULES_DIR = Path(__file__).parent / "rules"


@dataclass
class RuleLoadReport:
    loaded: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)


def load_rules(paths: Iterable[Path] | None = None,
               include_builtin: bool = True) -> tuple[list[SigmaRule], RuleLoadReport]:
    """Load .yml rules from the built-in pack and/or extra folders/files
    (e.g. a clone of the SigmaHQ repository)."""
    sources: list[Path] = []
    if include_builtin:
        sources.append(BUILTIN_RULES_DIR)
    sources.extend(Path(p) for p in (paths or []))
    rules: list[SigmaRule] = []
    report = RuleLoadReport()
    for src in sources:
        files = [src] if src.is_file() else sorted(
            list(src.rglob("*.yml")) + list(src.rglob("*.yaml")))
        for f in files:
            try:
                docs = list(yaml.safe_load_all(f.read_text(encoding="utf-8")))
            except (yaml.YAMLError, UnicodeDecodeError, OSError) as e:
                report.skipped.append((str(f), f"unreadable: {e}"))
                continue
            for doc in docs:
                if doc is None:
                    continue
                try:
                    rules.append(compile_rule(doc, str(f)))
                    report.loaded += 1
                except (UnsupportedRule, ValueError, re.error, TypeError) as e:
                    report.skipped.append((str(f), str(e)))
    return rules, report


class SigmaEngine:
    """Evaluate a set of compiled rules against events."""

    def __init__(self, rules: list[SigmaRule]) -> None:
        self.rules = rules

    def match(self, ev: dict[str, Any]) -> list[SigmaRule]:
        family = classify_channel(ev)
        event_id = ev.get("event_id") or 0
        view = event_view(ev)
        return [r for r in self.rules if r.matches(family, event_id, view)]
