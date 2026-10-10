"""Direct OSV.dev integration (`docs/competitive-gap-analysis.md`'s
"Direct OSV/NVD/GHSA integration" gap — SCA was fully delegated to
pip-audit/Trivy/Checkov's own embedded advisory data; nothing called
osv.dev, nvd.nist.gov or GHSA's API directly). Covers npm (`OsvEngine`) and
exactly-pinned PyPI requirements (`OsvPypiEngine`), sharing a common base.
See `engine.py` for what each closes and what it deliberately does not.
"""
