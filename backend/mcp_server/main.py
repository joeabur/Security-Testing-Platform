"""The MCP stdio transport: one newline-delimited JSON-RPC message per line
on stdin, one back on stdout — the same framing every other stdio MCP
server uses, so this drops into an MCP client's server list (Claude
Desktop's `mcpServers` config, or any equivalent) unmodified.

Credentials come from `aegis_cli`'s own config (`AEGIS_API_KEY`,
`AEGIS_BASE_URL`, `AEGIS_ORGANIZATION`, or `aegis-ai login`'s saved
profile) — the same credential an operator already has for the CLI, not a
new kind of secret to provision.
"""

from __future__ import annotations

import json
import sys

from aegis_cli.client import ApiClient
from aegis_cli.config import ENV_ORG, ENV_TOKEN, Profile
from mcp_server.server import McpDispatcher


def main() -> int:
    profile = Profile.load()
    if not profile.token:
        print(f"error: no API key. Set {ENV_TOKEN} or run `aegis-ai login`.", file=sys.stderr)
        return 1
    if not profile.organization_id:
        print(f"error: no organization. Set {ENV_ORG} or run `aegis-ai login`.", file=sys.stderr)
        return 1

    client = ApiClient(profile.base_url, profile.token)
    dispatcher = McpDispatcher(client, profile.organization_id)

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            # Not a JSON-RPC message at all — nothing sane to reply with,
            # and no request id to address a response to even if there
            # were.
            continue
        if not isinstance(message, dict):
            continue
        response = dispatcher.handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
