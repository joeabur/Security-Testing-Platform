"""An MCP-compatible server over the platform's native agent tools.

Satisfies the "External AI/API Integration... MCP-compatible interfaces"
requirement (Agent Phase 6) and the pentest module's own pending "external
API / MCP surface" task: one package, not two, serving both.

Built the same way `aegis_cli` is: a thin client over the platform's own
authenticated REST API, via an API key, with no other way to reach the
platform. There is no import of `app.core.agent` anywhere in this package
— an external MCP client gets exactly what
`app/api/v1/routers/agent.py`'s `GET .../agent/tools` and
`POST .../agent/tools/{name}/call` give it, under exactly the RBAC,
tenant-isolation, rate-limiting and audit those endpoints already enforce.
There is no separate, weaker code path for an external agent to find.
"""
