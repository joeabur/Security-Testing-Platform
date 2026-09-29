"""The `kervy-ai` command line interface (docs/BUILD_SPEC.md §20).

Deliberately its own top-level package rather than a module inside `app/`.
§26 Phase 10 requires that "the CLI exercises the same API/scope engine as the
UI (no parallel weaker path)", and the cleanest way to guarantee that is
structural: this package holds no scope engine, no probes, no adapters and no
database session. It can only reach a target by asking the API to, which means
every request it causes passes the same authorization gate and the same scope
engine a browser session does.

`tests/test_cli.py` asserts that boundary rather than trusting it.
"""

VERSION = "0.1.0"
