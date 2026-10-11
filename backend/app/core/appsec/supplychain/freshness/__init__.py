"""Supply-chain "freshly-published dependency version" signal
(`docs/supply-chain.md`'s "no registry lookup... no 'package published
yesterday' signal" gap).

Closes the publish-recency half of that gap only. The other half —
dependency-confusion detection ("does this *private* name also exist
publicly?") — needs an operator-declared concept of which dependency names
are internal, which does not exist anywhere in this codebase's schema
today; building that is a separate, larger feature, not attempted here.
See `engine.py` for what this does and does not claim.
"""
