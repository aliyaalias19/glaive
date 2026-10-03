"""Pseudonymise case data before it reaches a cloud model.

Incident evidence is full of personal and internal data: account names,
e-mail addresses, machine names, internal IP addresses, Windows SIDs. Sending
that to a model hosted abroad can break data-protection law (GDPR, Malaysia's
PDPA, China's PIPL) or a client contract. GLAIVE replaces each such value with
a stable token before a request leaves the machine and puts the real value
back in the reply:

    WS-FIN-07.corp.example  ->  HOST_1        j.doe@corp.example  ->  EMAIL_1
    CORP\\jdoe / jdoe         ->  USER_1        10.20.4.17          ->  IP_1
    S-1-5-21-...-1104       ->  SID_1         corp.example        ->  DOMAIN_1

The same value always gets the same token within an investigation, so the
model can still reason ("USER_1 logged on to HOST_2, then..."). The tool calls
and findings it sends back are translated to real values before they run, so
the verification gate always checks the real evidence.

Kept as they are, because the model needs them to recognise the attack:
public IP addresses and domains, file names and hashes, command lines, rule
titles. A command line can still contain a secret; use local-only mode
(GLAIVE_PRIVACY=local-only) when nothing may leave the machine.

    GLAIVE_PRIVACY=pseudonymize   default: mask for cloud models, not local ones
    GLAIVE_PRIVACY=local-only     refuse cloud models; local models only
    GLAIVE_PRIVACY=off            send case data unchanged
"""
from __future__ import annotations

import ipaddress
import os
import re
import threading
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit

MODES = ("pseudonymize", "local-only", "off")
PREFIX = {"user": "USER", "host": "HOST", "ip": "IP", "email": "EMAIL", "sid": "SID",
          "domain": "DOMAIN"}

# Built-in accounts and SIDs that identify nobody.
_GENERIC_USERS = frozenset({
    "system", "local service", "network service", "localservice", "networkservice",
    "anonymous logon", "administrator", "administrators", "guest", "defaultaccount", "users",
    "everyone", "nt authority", "builtin", "window manager", "font driver host", "dwm-1",
    "umfd-0", "umfd-1", "public", "default", "all users", "-", "n/a", "none", "null", "user",
    "admin", "root", "test", "operator", "backup", "support", "service", "localhost",
})
# "HKLM\SOFTWARE" and friends look like DOMAIN\user but are registry paths.
_NOT_DOMAINS = frozenset({"hklm", "hkcu", "hku", "hkcr", "hkcc", "hkey_local_machine",
                          "hkey_current_user", "hkey_users", "hkey_classes_root", "nt",
                          "authority", "builtin", "font", "window", "system32", "syswow64"})
_GENERIC_SID = re.compile(r"(?i)^S-1-(0|1|2|3|5-(1[0-9]|[1-9]|32-\d+|80-.*|90-.*|96-.*))$")

_EMAIL = re.compile(r"(?i)(?<![\w.+-])[a-z0-9._%+-]{1,64}@[a-z0-9.-]+\.[a-z]{2,24}(?![\w-])")
_SID = re.compile(r"(?i)(?<![\w-])S-1-5-21(?:-\d+){3,4}(?![\w-])")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
# C:\Users\<name>\  (also with JSON-escaped backslashes)
_PROFILE = re.compile(r"(?i)\\+users\\+([^\\/:*?\"<>|\s]{2,64})\\+")
_FILE_EXT = re.compile(r"(?i)\.(exe|dll|sys|evtx|log|txt|ps1|bat|cmd|dat|ini|xml|json|lnk|tmp)$")
# DOMAIN\user (also JSON-escaped)
_DOMAIN_USER = re.compile(r"(?<![\w\\])([A-Za-z][\w-]{1,30})\\{1,2}([A-Za-z][\w.$-]{1,63})(?![\w\\])")


def privacy_mode(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    mode = (env.get("GLAIVE_PRIVACY") or "pseudonymize").strip().lower()
    if mode not in MODES:
        raise ValueError(f"GLAIVE_PRIVACY must be one of {MODES}, not {mode!r}")
    return mode


def is_local_url(url: str | None) -> bool:
    """True for localhost and private-network addresses (an on-premises
    vLLM / Ollama / LM Studio server), false for anything on the internet."""
    if not url:
        return False
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return False
    # Single-label names (http://gpu-box:8000) only resolve on the local network.
    if host in ("localhost", "host.docker.internal") or host.endswith(".local") or \
            ("." not in host and ":" not in host):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def is_local_provider(provider: Any) -> bool:
    return provider.name == "ollama" or is_local_url(getattr(provider, "base_url", None))


# Internal address space. Python's is_private also covers documentation
# ranges (203.0.113.0/24 ...), which stand in for public addresses in examples.
_INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "fc00::/7", "fe80::/10"))


def is_internal_ip(text: str) -> bool:
    """RFC 1918, carrier-grade NAT, link-local and IPv6 private addresses."""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return any(ip in net for net in _INTERNAL_NETS if ip.version == net.version)


def _boundary(value: str) -> str:
    # Not inside a longer name or number: "WS01" must not match inside "WS010"
    # or "WS01.corp.example" (that FQDN has its own token). An underscore is a
    # boundary, because tools put host names in file names ("WS01_Security").
    return rf"(?<![A-Za-z0-9.-]){re.escape(value)}(?![A-Za-z0-9-]|\.[A-Za-z0-9])"


class Pseudonymizer:
    """Reversible value -> token mapping for one investigation (thread-safe)."""

    def __init__(self) -> None:
        self._fwd: dict[str, str] = {}      # lower(value) -> token
        self._rev: dict[str, str] = {}      # lower(token) -> value (first seen spelling)
        self._kind_counts: Counter[str] = Counter()
        self._lock = threading.Lock()
        self._mask_re: re.Pattern[str] | None = None
        self._unmask_re: re.Pattern[str] | None = None
        self.replacements = 0

    # ---- learning ---------------------------------------------------------------

    def add(self, kind: str, value: str | None) -> str | None:
        """Register a value; returns its token (None if it is not worth masking)."""
        if not value:
            return None
        v = value.strip()
        low = v.lower()
        if len(v) < 3 or low in _GENERIC_USERS or (kind == "sid" and _GENERIC_SID.match(v)):
            return None
        if kind == "ip" and not is_internal_ip(v):
            return None
        with self._lock:
            if low in self._fwd:
                return self._fwd[low]
            self._kind_counts[kind] += 1
            token = f"{PREFIX[kind]}_{self._kind_counts[kind]}"
            self._fwd[low] = token
            self._rev[token.lower()] = v
            self._mask_re = self._unmask_re = None
            return token

    def alias(self, value: str, token: str) -> None:
        """Map another spelling (a short host name) to an existing token."""
        if value and len(value) >= 3 and value.lower() not in _GENERIC_USERS:
            with self._lock:
                self._fwd.setdefault(value.lower(), token)
                self._mask_re = None

    def learn_text(self, text: str) -> None:
        """Pick up values that have a recognisable shape."""
        if not text:
            return
        for m in _EMAIL.finditer(text):
            self.add("email", m.group(0))
            self.add("domain", m.group(0).split("@", 1)[1])
        for m in _SID.finditer(text):
            self.add("sid", m.group(0))
        for m in _IPV4.finditer(text):
            self.add("ip", m.group(0))
        for m in _PROFILE.finditer(text):
            self.add("user", m.group(1))
        for m in _DOMAIN_USER.finditer(text):
            dom, user = m.group(1), m.group(2)
            if dom.lower() in _NOT_DOMAINS:
                continue
            if dom.upper() == dom and not user.endswith("$") and not _FILE_EXT.search(user):
                self.add("user", user)

    def learn_graph(self, graph: Any) -> None:
        """Register the users, hosts, SIDs and internal addresses of a case."""
        for n in graph.find_nodes("User"):
            sid = getattr(n, "sid", None) or ""
            if sid.upper().startswith("S-1-"):
                self.add("sid", sid)
            self.add("user", getattr(n, "username", None))
        for n in graph.find_nodes("Host"):
            name = getattr(n, "hostname", "") or ""
            token = self.add("host", name)
            if token and "." in name:
                short, _, dom = name.partition(".")
                self.alias(short, token)
                self.add("domain", dom)
        for n in graph.find_nodes("NetworkEndpoint"):
            self.add("ip", getattr(n, "remote_addr", None))

    # ---- translating --------------------------------------------------------------

    def _patterns(self) -> tuple[re.Pattern[str] | None, re.Pattern[str] | None]:
        with self._lock:
            if self._mask_re is None and self._fwd:
                vals = sorted(self._fwd, key=len, reverse=True)  # longest first
                self._mask_re = re.compile("|".join(_boundary(v) for v in vals), re.I)
            if self._unmask_re is None and self._rev:
                toks = sorted(self._rev, key=len, reverse=True)
                self._unmask_re = re.compile(
                    "|".join(rf"(?<![A-Za-z0-9]){re.escape(t)}(?![0-9])" for t in toks), re.I)
            return self._mask_re, self._unmask_re

    def mask(self, text: str | None) -> str | None:
        if not text:
            return text
        pat, _ = self._patterns()
        if pat is None:
            return text
        out, n = pat.subn(lambda m: self._fwd.get(m.group(0).lower(), m.group(0)), text)
        self.replacements += n
        return out

    def unmask(self, text: str | None) -> str | None:
        if not text:
            return text
        _, pat = self._patterns()
        if pat is None:
            return text
        return pat.sub(lambda m: self._rev.get(m.group(0).lower(), m.group(0)), text)

    def _walk(self, obj: Any, fn: Any) -> Any:
        if isinstance(obj, str):
            return fn(obj)
        if isinstance(obj, list):
            return [self._walk(x, fn) for x in obj]
        if isinstance(obj, tuple):
            return tuple(self._walk(x, fn) for x in obj)
        if isinstance(obj, dict):
            return {k: self._walk(v, fn) for k, v in obj.items()}
        return obj

    def mask_obj(self, obj: Any) -> Any:
        return self._walk(obj, self.mask)

    def unmask_obj(self, obj: Any) -> Any:
        return self._walk(obj, self.unmask)

    # ---- messages ------------------------------------------------------------------

    def mask_messages(self, messages: Iterable[Any]) -> list[Any]:
        """Copies of the messages with case data masked (the originals are
        kept, so the conversation history stays real). System prompts are
        GLAIVE's own text and are sent unchanged."""
        msgs = list(messages)
        for m in msgs:
            if m.role != "system":
                self.learn_text(m.content or "")
        return [m if m.role == "system" else self._translate(m, self.mask, self.mask_obj)
                for m in msgs]

    def unmask_message(self, message: Any) -> Any:
        return self._translate(message, self.unmask, self.unmask_obj)

    def _translate(self, m: Any, text_fn: Any, obj_fn: Any) -> Any:
        import json

        calls = []
        for c in m.tool_calls:
            args = obj_fn(c.arguments)
            raw = text_fn(c.raw_arguments) if c.parse_error or not c.raw_arguments \
                else json.dumps(args)
            calls.append(replace(c, arguments=args, raw_arguments=raw))
        return replace(m, content=text_fn(m.content), tool_calls=calls,
                       extra=obj_fn(m.extra) if m.extra else m.extra)

    def summary(self) -> dict[str, int]:
        return {k: v for k, v in sorted(self._kind_counts.items())}
