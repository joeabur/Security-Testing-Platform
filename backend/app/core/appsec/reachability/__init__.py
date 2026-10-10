"""Reachability analysis foundation (`docs/competitive-gap-analysis.md`'s
"Reachability analysis" gap: only *network* reachability existed; no
code-level reachability of a vulnerable dependency) — import detection, and
now symbol-usage detection (does the code also call something from the
imported module). See `python_imports.py` for what this closes and what it
deliberately does not.
"""
