"""The native AI agent: a structured, permission-gated tool layer on top of
`app.core.assistant`'s provider abstraction, prompt discipline, and
evidence-fencing — extended with multi-provider configuration, tool calling,
and short-lived investigation orchestration.

Zero-persistence by default (docs/guardrails.md §1.1, §"no AI-side memory"):
conversations, prompts, responses, and tool output are never written to the
database. `AgentContext` is built per request and discarded when it ends;
`app/models/agent.py` is the complete, closed set of what this subsystem is
allowed to persist, and `tests/security/test_agent_boundary.py` pins it.
"""
