"""The closed list of tools the native agent may call.

Mirrors `appsec_engines()`'s "explicitly registered, not auto-discovered"
idiom (`app/core/appsec/registry.py`): a tool exists because it is listed
here, never because a module happened to define one.
"""

from __future__ import annotations

from app.core.agent.tools import assets, findings, runs, workflows
from app.core.agent.tools.contract import Tool


def agent_tools() -> list[Tool]:
    return [
        assets.SEARCH_ASSETS,
        assets.GET_ASSET,
        findings.SEARCH_FINDINGS,
        findings.GET_FINDING,
        runs.GET_SCAN_STATUS,
        runs.GET_SCAN_RESULTS,
        workflows.GET_WORKFLOW_STATUS,
    ]


def tools_by_name() -> dict[str, Tool]:
    return {tool.name: tool for tool in agent_tools()}
