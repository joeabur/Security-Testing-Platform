"""Reachability analysis foundation (`docs/competitive-gap-analysis.md`'s
"Reachability analysis" gap: only *network* reachability existed; no
code-level reachability of a vulnerable dependency) — import detection, and
symbol-usage detection (does the code also call something from the
imported module). Covers Python (`python_imports.py`, AST-based) and
npm/JS (`js_imports.py`, regex/line-based — no JS parser dependency
exists), sharing the language-agnostic shapes in `shapes.py`. See each
module for what it closes and what it deliberately does not.
"""
