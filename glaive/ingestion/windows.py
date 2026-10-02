"""Parser for Windows Security, System, Sysmon and PowerShell events.

Turns normalized event dicts (from evtx_adapter or jsonl) into typed graph
nodes and edges. Every node and edge carries the event's own evidence hash.

Coverage:
  Security    4624/4625 logons, 4688 process creation, 4720 user created,
              4732/4728/4756 group membership, 4698 scheduled task created
  System      7045 service installed
  Sysmon      1 process create, 3 network connection, 11 file create,
              12/13 registry, 22 DNS query
  PowerShell  4104 script block

Process identity across sources
-------------------------------
A process seen by both Security 4688 and Sysmon 1 should be ONE node so the
Spawned edge collects two independent confirmations (and the gate can then
call it 'confirmed'). The two logs stamp the same creation with timestamps a
few milliseconds apart, so process start times are truncated to the second
for identity. Later events that only know a PID (network, file, registry) are
resolved to the most recent process with that PID that started before them.

Every event also gets a list of the entity keys it touched
(ParseResult.event_entities), which the detection engine uses to link alerts
to the processes, users and hosts they are about.
"""
from __future__ import annotations

import logging
import ntpath
import re
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from pydantic import Field, ValidationError

from glaive.graph.base import Edge, Node
from glaive.graph.edges import (
    AuthenticatedAs,
    Connected,
    Logon,
    Modified,
    Persisted,
    Ran,
    References,
    Spawned,
    Wrote,
)
from glaive.graph.nodes import (
    File,
    Host,
    NetworkEndpoint,
    Process,
    RegistryKey,
    ScheduledTask,
    ScriptBlock,
    Service,
    User,
)
from glaive.ingestion.base import Parser, ParseResult

logger = logging.getLogger(__name__)

SECURITY = "security"
SYSTEM = "system"
SYSMON = "sysmon"
POWERSHELL = "powershell"
DEFENDER = "defender"


def classify_channel(event: dict[str, Any]) -> str:
    """Map an event to a log family from its channel/provider name."""
    ch = (event.get("channel") or "").lower()
    prov = (event.get("provider") or "").lower()
    if "sysmon" in ch or "sysmon" in prov:
        return SYSMON
    if "windows defender" in ch or "windows defender" in prov:
        return DEFENDER
    if "powershell" in ch or "powershell" in prov:
        return POWERSHELL
    if ch == "security" or "security-auditing" in prov:
        return SECURITY
    if ch == "system":
        return SYSTEM
    return ch or "unknown"


def parse_time(ts: str | None) -> datetime | None:
    """ISO / Sysmon 'YYYY-MM-DD HH:MM:SS.fff' -> tz-aware UTC datetime."""
    if not ts:
        return None
    s = ts.strip().replace(" ", "T", 1).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _second(dt: datetime | None) -> datetime | None:
    return dt.replace(microsecond=0) if dt else None


def _int(value: Any) -> int | None:
    """Parse '1234', '0x4d2' or 1234; None if impossible."""
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    v = str(value).strip()
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    except ValueError:
        return None


def _basename(path: str | None) -> str | None:
    return ntpath.basename(path) if path else None


_PRIVATE = re.compile(
    r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|fe80:|fc|fd)", re.I)


def is_internal_ip(ip: str) -> bool:
    return bool(_PRIVATE.match(ip or ""))


_HIVES = {
    "HKLM": "HKLM", "HKEY_LOCAL_MACHINE": "HKLM",
    "HKU": "HKU", "HKEY_USERS": "HKU",
    "HKCU": "HKCU", "HKEY_CURRENT_USER": "HKCU",
    "HKCR": "HKCR", "HKEY_CLASSES_ROOT": "HKCR",
}


def split_registry_path(target: str) -> tuple[str, str, str | None]:
    """'HKLM\\SOFTWARE\\...\\Run\\evil' -> ('HKLM', 'SOFTWARE\\...\\Run', 'evil')."""
    t = target.replace("/", "\\").strip("\\")
    # Kernel-style paths: \REGISTRY\MACHINE\... and \REGISTRY\USER\...
    for prefix, hive in (("REGISTRY\\MACHINE", "HKLM"), ("REGISTRY\\USER", "HKU")):
        if t.upper().startswith(prefix):
            t = hive + t[len(prefix):]
            break
    first, _, rest = t.partition("\\")
    hive = _HIVES.get(first.upper(), first.upper() or "UNKNOWN")
    key_path, _, value = rest.rpartition("\\")
    if not key_path:  # no value component
        return hive, rest, None
    return hive, key_path, value or None


class WindowsParseResult(ParseResult):
    """ParseResult plus per-event entity links and stats."""

    event_entities: dict[str, list[tuple[str, tuple]]] = Field(default_factory=dict)
    events_by_family: dict[str, int] = Field(default_factory=dict)
    events_used: int = 0
    events_ignored: int = 0
    events_malformed: int = 0


class WindowsEventParser(Parser):
    """Security / System / Sysmon / PowerShell events -> graph."""

    source_type = "Windows event log"

    def parse(self, source: Any) -> WindowsParseResult:
        events = sorted(
            (e for e in source if isinstance(e, dict)),
            key=lambda e: e.get("time_created") or "",
        )
        self._r = WindowsParseResult()
        self._nodes: dict[tuple, Node] = {}
        self._edges: dict[tuple, Edge] = {}
        # (host, pid) -> list of process keys, for PID resolution
        self._pid_index: dict[tuple[str, int], list[tuple]] = defaultdict(list)

        handlers = {
            (SECURITY, 4624): self._logon, (SECURITY, 4625): self._logon,
            (SECURITY, 4688): self._sec_process,
            (SECURITY, 4720): self._user_created,
            (SECURITY, 4728): self._group_add, (SECURITY, 4732): self._group_add,
            (SECURITY, 4756): self._group_add,
            (SECURITY, 4698): self._task_created,
            (SYSTEM, 7045): self._service_installed,
            (SYSMON, 1): self._sysmon_process, (SYSMON, 3): self._sysmon_network,
            (SYSMON, 11): self._sysmon_file, (SYSMON, 12): self._sysmon_registry,
            (SYSMON, 13): self._sysmon_registry, (SYSMON, 22): self._sysmon_dns,
            (POWERSHELL, 4104): self._script_block,
        }

        for ev in events:
            family = classify_channel(ev)
            self._r.events_by_family[family] = self._r.events_by_family.get(family, 0) + 1
            handler = handlers.get((family, ev.get("event_id")))
            if handler is None or not ev.get("_evidence_hash"):
                self._r.events_ignored += 1
                continue
            self._ev = ev
            self._touched: list[tuple[str, tuple]] = []
            try:
                host = self._host(ev)
                handler(ev, ev.get("raw_data") or {}, host)
                self._r.events_used += 1
            except (KeyError, ValueError, TypeError, ValidationError) as e:
                logger.debug("Malformed %s event %s: %s", family, ev.get("event_id"), e)
                self._r.events_malformed += 1
                continue
            uid = ev.get("_uid")
            if uid:
                self._r.event_entities[uid] = self._touched

        self._r.nodes = list(self._nodes.values())
        self._r.edges = list(self._edges.values())
        return self._r

    # ---- building blocks ---------------------------------------------------------

    def _prov(self) -> dict[str, str]:
        ev = self._ev
        return {"evidence_hash": ev["_evidence_hash"],
                "derivation": ev.get("_derivation") or self._derivation()}

    def _add_node(self, node: Node, role: str | None = None) -> tuple:
        key = node.canonical_key()
        if key in self._nodes:
            self._nodes[key].merge_into(node)
        else:
            self._nodes[key] = node
        if role:
            self._touched.append((role, key))
        return key

    def _add_edge(self, edge: Edge) -> None:
        key = edge.canonical_key()
        if key in self._edges:
            self._edges[key].merge_into(edge)
        else:
            self._edges[key] = edge

    def _host(self, ev: dict) -> tuple:
        hostname = ev["computer"]
        return self._add_node(Host(hostname=hostname, **self._prov()), "host")

    def _user(self, sid: str | None, name: str | None, domain: str | None,
              role: str) -> tuple | None:
        if not name and not sid:
            return None
        if not sid or sid in ("S-1-0-0", "-"):
            # Failed logons for unknown accounts carry the NULL SID. Use a
            # name-based identity so different usernames stay distinct.
            if not name or name == "-":
                return None
            sid = f"UNRESOLVED:{(domain or '').upper()}\\{name.lower()}"
        account_type = "well-known" if re.fullmatch(r"S-1-5-(18|19|20)", sid) else None
        return self._add_node(
            User(sid=sid, username=None if name in (None, "-") else name,
                 domain=None if domain in (None, "-") else domain,
                 account_type=account_type, **self._prov()),
            role)

    def _process(self, host: str, pid: int, image: str | None, start: datetime | None,
                 observed_by: str, command_line: str | None = None,
                 parent_pid: int | None = None, sha256: str | None = None,
                 role: str | None = None) -> tuple:
        existing = self._nodes.get(("Process", host, pid, _second(start)))
        if existing is not None:
            if image and existing.name.startswith("pid_"):
                existing.name = _basename(image) or existing.name
                existing.image_path = existing.image_path or image
            if image is None and command_line is None:
                if observed_by not in existing.observed_by:
                    existing.observed_by.append(observed_by)
                key = existing.canonical_key()
                if role:
                    self._touched.append((role, key))
                return key
        node = Process(
            host_hostname=host, pid=pid,
            name=_basename(image) or f"pid_{pid}",
            image_path=image or None, command_line=command_line or None,
            parent_pid=parent_pid, start_time=_second(start), sha256=sha256,
            observed_by=[observed_by], **self._prov())
        key = self._add_node(node, role)
        if key not in self._pid_index[(host, pid)]:
            self._pid_index[(host, pid)].append(key)
        return key

    def _resolve_pid(self, host: str, pid: int, at: datetime | None, image: str | None,
                     observed_by: str, role: str) -> tuple:
        """Find the process with this PID alive at `at`, else create a stub."""
        best: tuple | None = None
        for key in self._pid_index.get((host, pid), []):
            start = key[3]
            if start is None or at is None or start <= at:
                if best is None or (start is not None and (best[3] is None or start > best[3])):
                    best = key
        if best is not None:
            node = self._nodes[best]
            if image and not node.image_path:
                node.image_path = image
            if image and node.name.startswith("pid_"):
                node.name = _basename(image) or node.name
            if observed_by not in node.observed_by:
                node.observed_by.append(observed_by)
            self._touched.append((role, best))
            return best
        return self._process(host, pid, image, None, observed_by, role=role)

    # ---- Security ------------------------------------------------------------------

    def _logon(self, ev: dict, d: dict, host: tuple) -> None:
        success = ev["event_id"] == 4624
        user = self._user(d.get("TargetUserSid"), d.get("TargetUserName"),
                          d.get("TargetDomainName"), "user")
        if user is None:
            return
        ip = d.get("IpAddress")
        self._add_edge(Logon(
            source_key=user, target_key=host, timestamp=parse_time(ev["time_created"]),
            logon_type=_int(d.get("LogonType")),
            source_ip=None if ip in (None, "", "-") else ip,
            success=success,
            failure_reason=None if success else (d.get("SubStatus") or d.get("Status")),
            confirmed_by=[f"evtx_{ev['event_id']}"], **self._prov()))

    def _sec_process(self, ev: dict, d: dict, host: tuple) -> None:
        h = host[1]
        t = parse_time(ev["time_created"])
        pid, ppid = _int(d["NewProcessId"]), _int(d.get("ProcessId"))
        if pid is None:
            raise ValueError("4688 without NewProcessId")
        parent = None
        if ppid is not None:
            parent = self._resolve_pid(h, ppid, t, d.get("ParentProcessName"),
                                       "evtx_4688", "parent")
        child = self._process(h, pid, d.get("NewProcessName"), t, "evtx_4688",
                              command_line=d.get("CommandLine"), parent_pid=ppid,
                              role="process")
        if parent:
            self._add_edge(Spawned(source_key=parent, target_key=child, timestamp=_second(t),
                                   confirmed_by=["evtx_4688"], **self._prov()))
        user = self._user(d.get("SubjectUserSid"), d.get("SubjectUserName"),
                          d.get("SubjectDomainName"), "user")
        if user:
            self._add_edge(AuthenticatedAs(source_key=child, target_key=user, **self._prov()))

    def _user_created(self, ev: dict, d: dict, host: tuple) -> None:
        self._user(d.get("TargetSid"), d.get("TargetUserName") or d.get("SamAccountName"),
                   d.get("TargetDomainName"), "target")
        self._user(d.get("SubjectUserSid"), d.get("SubjectUserName"),
                   d.get("SubjectDomainName"), "user")

    def _group_add(self, ev: dict, d: dict, host: tuple) -> None:
        member_name = d.get("MemberName") or ""
        # MemberName is a DN such as CN=bob,CN=Users,DC=corp,DC=local
        m = re.match(r"CN=([^,]+)", member_name)
        self._user(d.get("MemberSid"), m.group(1) if m else (member_name or None), None,
                   "target")
        self._user(d.get("SubjectUserSid"), d.get("SubjectUserName"),
                   d.get("SubjectDomainName"), "user")

    def _task_created(self, ev: dict, d: dict, host: tuple) -> None:
        content = d.get("TaskContent") or ""
        cmd = re.search(r"<Command>(.*?)</Command>", content, re.S)
        args = re.search(r"<Arguments>(.*?)</Arguments>", content, re.S)
        author = re.search(r"<Author>(.*?)</Author>", content, re.S)
        task = self._add_node(ScheduledTask(
            host_hostname=host[1], task_path=d["TaskName"],
            command=cmd.group(1).strip() if cmd else None,
            arguments=args.group(1).strip() if args else None,
            author=author.group(1).strip() if author else None,
            **self._prov()), "task")
        if cmd:
            f = self._add_node(File(host_hostname=host[1], full_path=cmd.group(1).strip(),
                                    referenced_by=["evtx_4698"], **self._prov()), "file")
            self._add_edge(References(source_key=task, target_key=f,
                                      reference_type="task_action", **self._prov()))
            self._add_edge(Persisted(source_key=f, target_key=task,
                                     timestamp=parse_time(ev["time_created"]),
                                     mechanism="scheduled_task", confirmed_by=["evtx_4698"],
                                     **self._prov()))
        self._user(d.get("SubjectUserSid"), d.get("SubjectUserName"),
                   d.get("SubjectDomainName"), "user")

    # ---- System --------------------------------------------------------------------

    def _service_installed(self, ev: dict, d: dict, host: tuple) -> None:
        image = d.get("ImagePath") or None
        svc = self._add_node(Service(
            host_hostname=host[1], service_name=d["ServiceName"], image_path=image,
            start_type=d.get("StartType") or None, service_account=d.get("AccountName") or None,
            **self._prov()), "service")
        if image:
            f = self._add_node(File(host_hostname=host[1], full_path=image,
                                    referenced_by=["evtx_7045"], **self._prov()), "file")
            self._add_edge(References(source_key=svc, target_key=f,
                                      reference_type="service_image", **self._prov()))
            self._add_edge(Persisted(source_key=f, target_key=svc,
                                     timestamp=parse_time(ev["time_created"]),
                                     mechanism="service", confirmed_by=["evtx_7045"],
                                     **self._prov()))

    # ---- Sysmon --------------------------------------------------------------------

    def _sysmon_time(self, ev: dict, d: dict) -> datetime | None:
        return parse_time(d.get("UtcTime")) or parse_time(ev["time_created"])

    def _sysmon_process(self, ev: dict, d: dict, host: tuple) -> None:
        h = host[1]
        t = self._sysmon_time(ev, d)
        pid, ppid = _int(d["ProcessId"]), _int(d.get("ParentProcessId"))
        if pid is None:
            raise ValueError("Sysmon 1 without ProcessId")
        sha = None
        m = re.search(r"SHA256=([0-9A-Fa-f]{64})", d.get("Hashes") or "")
        if m:
            sha = m.group(1).lower()
        parent = None
        if ppid is not None:
            parent = self._resolve_pid(h, ppid, t, d.get("ParentImage"), "sysmon_1", "parent")
            pnode = self._nodes[parent]
            if not pnode.command_line and d.get("ParentCommandLine"):
                pnode.command_line = d["ParentCommandLine"]
        child = self._process(h, pid, d.get("Image"), t, "sysmon_1",
                              command_line=d.get("CommandLine"), parent_pid=ppid, sha256=sha,
                              role="process")
        if parent:
            self._add_edge(Spawned(source_key=parent, target_key=child, timestamp=_second(t),
                                   confirmed_by=["sysmon_1"], **self._prov()))
        user_name = d.get("User")
        if user_name:
            dom, _, name = user_name.rpartition("\\")
            user = self._user(None, name or user_name, dom or None, "user")
            if user:
                self._add_edge(AuthenticatedAs(source_key=child, target_key=user,
                                               **self._prov()))

    def _sysmon_network(self, ev: dict, d: dict, host: tuple) -> None:
        h = host[1]
        t = self._sysmon_time(ev, d)
        pid = _int(d.get("ProcessId"))
        dst, port = d.get("DestinationIp"), _int(d.get("DestinationPort"))
        if pid is None or not dst or port is None:
            raise ValueError("incomplete network event")
        proc = self._resolve_pid(h, pid, t, d.get("Image"), "sysmon_3", "process")
        ep = self._add_node(NetworkEndpoint(
            protocol=(d.get("Protocol") or "tcp").upper(), remote_addr=dst, remote_port=port,
            domain=d.get("DestinationHostname") or None, is_internal=is_internal_ip(dst),
            **self._prov()), "endpoint")
        initiated = (d.get("Initiated") or "").lower() == "true"
        self._add_edge(Connected(source_key=proc, target_key=ep, timestamp=_second(t),
                                 direction="outbound" if initiated else "inbound",
                                 local_port=_int(d.get("SourcePort")),
                                 confirmed_by=["sysmon_3"], **self._prov()))

    def _sysmon_file(self, ev: dict, d: dict, host: tuple) -> None:
        h = host[1]
        t = self._sysmon_time(ev, d)
        pid = _int(d.get("ProcessId"))
        target = d["TargetFilename"]
        f = self._add_node(File(host_hostname=h, full_path=target, on_disk=True,
                                btime=parse_time(d.get("CreationUtcTime")), **self._prov()),
                           "file")
        if pid is not None:
            proc = self._resolve_pid(h, pid, t, d.get("Image"), "sysmon_11", "process")
            self._add_edge(Wrote(source_key=proc, target_key=f, timestamp=_second(t),
                                 operation="create", confirmed_by=["sysmon_11"],
                                 **self._prov()))

    def _sysmon_registry(self, ev: dict, d: dict, host: tuple) -> None:
        h = host[1]
        t = self._sysmon_time(ev, d)
        hive, key_path, value = split_registry_path(d["TargetObject"])
        reg = self._add_node(RegistryKey(
            host_hostname=h, hive_name=hive, key_path=key_path, value_name=value,
            value_data=d.get("Details") or None, last_write_time=t, **self._prov()),
            "registry")
        pid = _int(d.get("ProcessId"))
        if pid is not None:
            proc = self._resolve_pid(h, pid, t, d.get("Image"), f"sysmon_{ev['event_id']}",
                                     "process")
            op = {"SetValue": "update", "CreateKey": "create", "DeleteKey": "delete",
                  "DeleteValue": "delete"}.get(d.get("EventType") or "", None)
            self._add_edge(Modified(source_key=proc, target_key=reg, timestamp=_second(t),
                                    operation=op, new_value=d.get("Details") or None,
                                    confirmed_by=[f"sysmon_{ev['event_id']}"], **self._prov()))

    def _sysmon_dns(self, ev: dict, d: dict, host: tuple) -> None:
        h = host[1]
        t = self._sysmon_time(ev, d)
        name = d["QueryName"]
        ep = self._add_node(NetworkEndpoint(protocol="DNS", remote_addr=name, remote_port=53,
                                            domain=name, **self._prov()), "endpoint")
        pid = _int(d.get("ProcessId"))
        if pid is not None:
            proc = self._resolve_pid(h, pid, t, d.get("Image"), "sysmon_22", "process")
            self._add_edge(Connected(source_key=proc, target_key=ep, timestamp=_second(t),
                                     direction="outbound", state="dns_query",
                                     confirmed_by=["sysmon_22"], **self._prov()))

    # ---- PowerShell ----------------------------------------------------------------

    def _script_block(self, ev: dict, d: dict, host: tuple) -> None:
        text = d.get("ScriptBlockText") or ""
        sb = self._add_node(ScriptBlock(
            host_hostname=host[1], script_block_id=d.get("ScriptBlockId") or f"rec{ev.get('_record_id')}",
            text=text[:20000], path=d.get("Path") or None,
            first_seen=parse_time(ev["time_created"]), **self._prov()), "script")
        # PowerShell/Operational records the hosting process in System/Execution,
        # which our adapters do not keep; link via _process_id when supplied.
        pid = _int(ev.get("_process_id"))
        if pid is not None:
            proc = self._resolve_pid(host[1], pid, parse_time(ev["time_created"]), None,
                                     "powershell_4104", "process")
            self._add_edge(Ran(source_key=proc, target_key=sb,
                               timestamp=_second(parse_time(ev["time_created"])),
                               **self._prov()))
