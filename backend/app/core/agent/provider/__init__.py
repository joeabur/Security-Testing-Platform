"""Concrete `AIProvider` implementations beyond `app.core.assistant`'s
OpenAI-compatible one — native Anthropic and Gemini wire formats — plus a
factory that builds one from an organization's configured `AgentProvider`
row rather than a single global setting.
"""
