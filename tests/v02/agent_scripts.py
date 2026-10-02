"""Scripted stand-ins for an LLM, shared by the agent tests.

They behave like a model: read the (spotlighted) tool results and decide the
next call. The Hunter script tries one hallucination first, which the gate
must stop.
"""
from __future__ import annotations

import json

from glaive.demo.case import C2
from glaive.llm.types import Message, ToolCall


def _payload(tool_msg: Message) -> dict:
    lines = (tool_msg.content or "").splitlines()
    return json.loads("\n".join(lines[1:-1]))  # strip the random <tool_result-xxxx> tags


def _call(name: str, **args) -> Message:  # noqa: ANN003
    return Message("assistant", None, tool_calls=[ToolCall(f"c-{name}", name, args)])


def hunter_script(messages: list[Message], tools: object) -> Message:
    """A competent but imperfect investigator: tries one hallucination first."""
    assistant_turns = sum(1 for m in messages if m.role == "assistant")
    last = messages[-1]
    st = hunter_script.state  # type: ignore[attr-defined]
    if assistant_turns == 0:
        return Message("assistant", "Plan: H1 phishing -> PowerShell; H2 C2 beacon; H3 discovery.",
                       tool_calls=[ToolCall("c0", "case_overview", {})])
    if assistant_turns == 1:
        return _call("query_graph", node_type="NetworkEndpoint",
                     filters=[{"field": "remote_port", "op": "eq", "value": 443},
                              {"field": "remote_addr", "op": "eq", "value": C2}])
    if assistant_turns == 2:
        st["endpoint"] = _payload(last)["nodes"][0]["canonical_key"]
        return _call("neighbors", canonical_key=st["endpoint"], edge_type="Connected")
    if assistant_turns == 3:
        st["proc"] = _payload(last)["neighbors"][0]["node"]["canonical_key"]
        return _call("commit_finding",
                     claim="svchost32.exe uploaded the finance database to 203.0.113.99",
                     supporting_node_keys=[st["proc"], st["endpoint"]], severity="critical")
    if assistant_turns == 4:
        st["rejected"] = _payload(last)["decision"]
        return _call("commit_finding",
                     claim=f"svchost32.exe (PID 7720) beaconed to {C2} on port 443 "
                           "(update-check.cdn-msft.example) every five minutes.",
                     supporting_node_keys=[st["proc"], st["endpoint"]],
                     confidence_hint="confirmed", severity="high", mitre_techniques=["T1071"],
                     rationale="Six Sysmon network events from the same process.")
    if assistant_turns == 5:
        return _call("query_graph", node_type="Process",
                     filters=[{"field": "name", "op": "eq", "value": "net.exe"}])
    if assistant_turns == 6:
        key = _payload(last)["nodes"][0]["canonical_key"]
        return _call("commit_finding",
                     claim='net.exe enumerated the "domain admins" group: '
                           'net group "domain admins" /domain.',
                     supporting_node_keys=[key], severity="low", mitre_techniques=["T1087.002"])
    return _call("finish", summary="Phishing led to C2, discovery, credential theft and "
                                   "ransomware preparation on the file server.")


def fresh_hunter_script():  # noqa: ANN202
    hunter_script.state = {}  # type: ignore[attr-defined]
    return hunter_script
