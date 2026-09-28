"""The agent's structured, permission-controlled tools.

Every tool wraps one existing platform capability — the same query or
service function its matching REST endpoint already calls, in-process,
under the caller's own `AgentContext` — never a second implementation of
it and never unrestricted database, shell, or HTTP access. See
`contract.py` for the `Tool` shape and `registry.py` for the closed list of
what exists.
"""
