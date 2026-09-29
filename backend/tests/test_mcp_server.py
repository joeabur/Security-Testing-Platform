"""`mcp_server.server.McpDispatcher`: the JSON-RPC 2.0 dispatch layer for
the tools/list + tools/call slice of MCP this server speaks, tested
against a fake `ApiClient` so no real HTTP call or process is involved —
the transport (`main.py`'s stdio loop) is exercised separately, if at all,
by construction rather than by these tests.
"""

from __future__ import annotations

from typing import Any

import pytest

from kervy_cli.client import CliError
from mcp_server.server import PROTOCOL_VERSION, McpDispatcher


class _FakeApiClient:
    """Records every call and answers from a canned response table, the
    same role `FakeProvider` plays for an `AIProvider` elsewhere in this
    test suite."""

    def __init__(self, responses: dict[tuple[str, str], Any]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def request(
        self, method: str, path: str, *, json_body: dict[str, Any] | None = None, **_: object
    ) -> Any:
        self.calls.append((method, path, json_body))
        key = (method, path)
        if key not in self._responses:
            raise CliError(f"no canned response for {method} {path}")
        response = self._responses[key]
        if isinstance(response, Exception):
            raise response
        return response


def _dispatcher(responses: dict[tuple[str, str], Any]) -> tuple[McpDispatcher, _FakeApiClient]:
    client = _FakeApiClient(responses)
    return McpDispatcher(client, "org-1"), client  # type: ignore[arg-type]


def test_initialize_reports_protocol_version_and_server_info() -> None:
    dispatcher, _client = _dispatcher({})

    response = dispatcher.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})

    assert response is not None
    assert response["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert response["result"]["serverInfo"]["name"] == "kervy-security"


def test_tools_list_translates_the_catalog_into_mcp_tool_descriptors() -> None:
    catalog = [
        {
            "name": "get_asset",
            "description": "Get one target by id.",
            "risk_level": "read_only",
            "minimum_role": "viewer",
            "input_schema": {"type": "object", "properties": {"target_id": {"type": "string"}}},
        }
    ]
    dispatcher, client = _dispatcher({("GET", "/organizations/org-1/agent/tools"): catalog})

    response = dispatcher.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})

    assert response is not None
    tools = response["result"]["tools"]
    assert tools == [
        {
            "name": "get_asset",
            "description": "Get one target by id.",
            "inputSchema": {"type": "object", "properties": {"target_id": {"type": "string"}}},
        }
    ]
    assert client.calls == [("GET", "/organizations/org-1/agent/tools", None)]


def test_tools_call_returns_the_tools_result_as_text_content() -> None:
    dispatcher, client = _dispatcher(
        {
            ("POST", "/organizations/org-1/agent/tools/get_asset/call"): {
                "tool_name": "get_asset",
                "status": "ok",
                "result": {"target": {"id": "abc", "name": "acme-api"}},
                "error": None,
                "duration_ms": 5,
            }
        }
    )

    response = dispatcher.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "get_asset", "arguments": {"target_id": "abc"}},
        }
    )

    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    assert "acme-api" in result["content"][0]["text"]
    assert client.calls == [
        (
            "POST",
            "/organizations/org-1/agent/tools/get_asset/call",
            {"params": {"target_id": "abc"}},
        )
    ]


def test_tools_call_marks_a_tool_level_failure_as_an_error_result() -> None:
    dispatcher, _client = _dispatcher(
        {
            ("POST", "/organizations/org-1/agent/tools/get_asset/call"): {
                "tool_name": "get_asset",
                "status": "tool_not_found",
                "result": None,
                "error": "target abc not found",
                "duration_ms": 3,
            }
        }
    )

    response = dispatcher.handle(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "get_asset", "arguments": {"target_id": "abc"}},
        }
    )

    assert response is not None
    result = response["result"]
    assert result["isError"] is True
    assert result["content"][0]["text"] == "target abc not found"


def test_tools_call_reports_a_platform_refusal_as_a_protocol_error() -> None:
    """A SENSITIVE tool called directly, an unknown tool, bad arguments —
    the platform's REST layer answers all of these with an HTTP error,
    which `ApiClient.request` turns into a `CliError`. This server reports
    that as a JSON-RPC error rather than a successful `tools/call` with
    `isError: true` — see server.py's own docstring for why."""
    dispatcher, _client = _dispatcher(
        {
            ("POST", "/organizations/org-1/agent/tools/start_scan/call"): CliError(
                "start_scan is a sensitive action and cannot be called directly"
            )
        }
    )

    response = dispatcher.handle(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "start_scan", "arguments": {}},
        }
    )

    assert response is not None
    assert "error" in response
    assert "sensitive" in response["error"]["message"]


def test_tools_call_requires_a_tool_name() -> None:
    dispatcher, _client = _dispatcher({})

    response = dispatcher.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {}})

    assert response is not None
    assert "error" in response


def test_an_unknown_method_with_an_id_is_a_json_rpc_error() -> None:
    dispatcher, _client = _dispatcher({})

    response = dispatcher.handle({"jsonrpc": "2.0", "id": 7, "method": "not/a/real/method"})

    assert response is not None
    assert response["error"]["code"] == -32601


def test_a_notification_never_gets_a_response_even_for_an_unknown_method() -> None:
    dispatcher, _client = _dispatcher({})

    # No "id" — a notification, per JSON-RPC 2.0.
    response = dispatcher.handle({"jsonrpc": "2.0", "method": "not/a/real/method"})

    assert response is None


def test_initialized_notification_is_a_silent_no_op() -> None:
    dispatcher, _client = _dispatcher({})

    response = dispatcher.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})

    assert response is None


@pytest.mark.parametrize("method", ["ping", "initialized"])
def test_trivial_methods_with_an_id_return_an_empty_result(method: str) -> None:
    dispatcher, _client = _dispatcher({})

    response = dispatcher.handle({"jsonrpc": "2.0", "id": 8, "method": method})

    assert response == {"jsonrpc": "2.0", "id": 8, "result": {}}
