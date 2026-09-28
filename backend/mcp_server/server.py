"""JSON-RPC 2.0 dispatch for the slice of MCP this server speaks.

Separated from the stdio transport (`main.py`) so it can be tested by
feeding it request dicts directly and reading back response dicts — no
process, no real stdin/stdout — the same reason `aegis_cli.main` keeps its
command functions apart from argv parsing.

Only three real methods: `initialize`, `tools/list`, `tools/call`. A
notification (a message with no `id`) never gets a response, success or
failure, per JSON-RPC — including an unknown-method notification, which is
silently dropped rather than answered with an error nobody asked for.
"""

from __future__ import annotations

import json
from typing import Any

from aegis_cli.client import ApiClient, CliError

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "aegis-ai-security"
SERVER_VERSION = "0.1.0"

# JSON-RPC 2.0 reserved server-error range, matching the codes most MCP
# clients already expect (method-not-found is the one standard code worth
# being specific about; everything else this server can fail on — a tool
# refusal, an HTTP error, a bad argument — is reported the same generic way
# the platform's own REST error already described it).
_METHOD_NOT_FOUND = -32601
_SERVER_ERROR = -32000


class _UnknownMethod(Exception):
    pass


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class McpDispatcher:
    """One platform organization's worth of tools, over one `ApiClient`."""

    def __init__(self, client: ApiClient, organization_id: str) -> None:
        self._client = client
        self._organization_id = organization_id

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params") or {}
        try:
            result = self._dispatch(method, params)
        except _UnknownMethod:
            return (
                None
                if request_id is None
                else _error(request_id, _METHOD_NOT_FOUND, f"unknown method {method!r}")
            )
        except CliError as exc:
            # The same refusal a native caller of the REST API would have
            # gotten — a role too low, an unknown tool, a SENSITIVE tool
            # called directly, bad arguments — reported as a protocol-level
            # error rather than a successful `tools/call` with `isError`,
            # a deliberate simplification: this server does not attempt to
            # distinguish "your request was malformed" from "the platform
            # refused it" the way a fuller MCP implementation might.
            return None if request_id is None else _error(request_id, _SERVER_ERROR, str(exc))
        if request_id is None:
            return None
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _dispatch(self, method: str | None, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return self._initialize()
        if method in ("initialized", "notifications/initialized", "ping"):
            return {}
        if method == "tools/list":
            return self._tools_list()
        if method == "tools/call":
            return self._tools_call(params)
        raise _UnknownMethod(method)

    def _initialize(self) -> dict[str, Any]:
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }

    def _tools_list(self) -> dict[str, Any]:
        catalog = self._client.request("GET", f"/organizations/{self._organization_id}/agent/tools")
        return {
            "tools": [
                {
                    "name": entry["name"],
                    "description": entry["description"],
                    "inputSchema": entry.get("input_schema") or {"type": "object"},
                }
                for entry in catalog
            ]
        }

    def _tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise CliError("tools/call requires a string 'name'")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise CliError("tools/call 'arguments' must be an object")

        outcome = self._client.request(
            "POST",
            f"/organizations/{self._organization_id}/agent/tools/{name}/call",
            json_body={"params": arguments},
        )
        is_error = outcome.get("status") != "ok"
        text = (
            outcome.get("error") or "the tool did not report a result"
            if is_error
            else json.dumps(outcome.get("result"), default=str)
        )
        return {"content": [{"type": "text", "text": text}], "isError": is_error}
