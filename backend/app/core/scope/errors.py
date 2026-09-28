class AuthorizationRequiredError(Exception):
    """No authorization record was resolved for the target. Run refused."""


class RoEValidationError(Exception):
    """The Rules of Engagement document failed schema validation. Run refused."""


class AssetScopeValidationError(Exception):
    """The asset_scope document (container/cloud/VM/domain/pentest) is
    missing, malformed, or declares an empty boundary where one is required.
    Same "ABORT RUN" semantics as RoEValidationError — an unstated scope for
    one of these asset kinds is never a permissive one."""
