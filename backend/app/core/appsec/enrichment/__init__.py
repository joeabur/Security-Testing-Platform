"""Direct NVD/GHSA advisory-detail enrichment
(`docs/competitive-gap-analysis.md`'s "Direct NVD/GHSA clients" gap).

This is additive, not a discovery mechanism. Both NVD's CVE API and
GHSA's advisory API are keyed by a CVE/GHSA id, not by package+version —
useful for enriching a finding that already names a verified advisory id
with CVSS/description detail, but not for discovering which CVEs apply
to a dependency the way `osv/`'s batch endpoint does. See
`advisory_detail.py` for what this closes and what it deliberately does
not.
"""
