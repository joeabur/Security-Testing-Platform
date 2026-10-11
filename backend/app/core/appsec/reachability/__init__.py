"""Reachability analysis foundation (`docs/competitive-gap-analysis.md`'s
"Reachability analysis" gap: only *network* reachability existed; no
code-level reachability of a vulnerable dependency) — import detection, and
symbol-usage detection (does the code also call something from the
imported module). Covers Python (`python_imports.py`, AST-based) and
npm/JS, Go, and Rust (`js_imports.py`/`go_imports.py`/`rust_imports.py`,
each regex/line-based — no parser dependency exists for any of them),
sharing the language-agnostic shapes in `shapes.py`. Java is deliberately
excluded — see `osv/engine.py`'s `OsvJavaEngine` for why. See each module
for what it closes and what it deliberately does not.
"""
