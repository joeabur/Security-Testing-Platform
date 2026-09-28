"""Domain/DNS assessment: discover subdomains, then check TLS and security
headers on whichever of them the rules of engagement actually authorize
probing further.

Discovery never expands what gets tested — see `engine.py`'s module
docstring for why an empty `allowed_subdomain_patterns` means "only the
root domain itself," the same fail-closed reading `asset_scope.py` already
documents for `DomainScope`.
"""
