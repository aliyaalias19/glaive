"""Compatibility helpers across mcp SDK major versions (1.x FastMCP, 2.x MCPServer)."""
from __future__ import annotations

import json
from typing import Any


def tool_payload(result: Any) -> dict[str, Any]:
    """Normalize the return of server.call_tool() to the tool's dict payload.

    Handles: mcp 1.x list[TextContent], mcp 1.x (content, structured) tuple,
    mcp 2.x CallToolResult, or a plain dict.
    """
    if isinstance(result, dict):
        return result
    if isinstance(result, tuple) and len(result) == 2:
        content, structured = result
        if isinstance(structured, dict) and structured:
            return structured.get("result", structured) if set(structured) == {"result"} else structured
        result = content
    structured = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
    if isinstance(structured, dict) and structured:
        return structured.get("result", structured) if set(structured) == {"result"} else structured
    if hasattr(result, "content"):
        result = result.content
    if isinstance(result, list) and result and hasattr(result[0], "text"):
        return json.loads(result[0].text)
    raise TypeError(f"Unexpected call_tool return shape: {type(result).__name__}")
