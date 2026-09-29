import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.core.config import get_settings

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def create_access_token(*, subject: uuid.UUID, extra_claims: dict[str, Any] | None = None) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": str(subject),
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        # A per-token id, so one issued token can be revoked without touching
        # any other (app/core/revocation/). Without this, "revoke this one
        # session" is not expressible — every JWT with the same subject and
        # roughly the same iat would be indistinguishable.
        "jti": str(uuid.uuid4()),
        # `iat` above is a standard JWT NumericDate: RFC 7519 defines it as
        # integer seconds, and PyJWT truncates a `datetime` claim to that on
        # encode. That is fine for the JWT's own semantics but is the wrong
        # thing to compare against `User.tokens_valid_after` (a microsecond-
        # precision Postgres column) for the "log out everywhere" cutoff — two
        # events in the same wall-clock second become indistinguishable, and
        # rounding either side to match only moves the race to the other
        # direction. `iat_us`, whole microseconds since the epoch, is a
        # private claim kept at full precision purely for that comparison, so
        # ordering two nearly-simultaneous events no longer depends on which
        # second they happened to fall in.
        "iat_us": int(now.timestamp() * 1_000_000),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


class InvalidTokenError(Exception):
    pass


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc

    # `jti` and `iat_us` are required, not merely expected. A token missing
    # either cannot be checked against revocation, and treating that as
    # "nothing to check, let it through" would be a downgrade attack: forge —
    # or simply strip a claim from — a token and it becomes unrevokable or
    # exempt from the "log out everywhere" cutoff. Every token this process
    # has ever issued carries both, so a token without them is malformed,
    # handled the same as a bad signature.
    if "jti" not in payload or not isinstance(payload["jti"], str):
        raise InvalidTokenError("token is missing its jti claim")
    if "iat_us" not in payload or not isinstance(payload["iat_us"], int):
        raise InvalidTokenError("token is missing its iat_us claim")
    return payload


def token_id(payload: dict[str, Any]) -> str:
    return str(payload["jti"])


def issued_at_precise(payload: dict[str, Any]) -> datetime:
    """Full microsecond precision — see the `iat_us` comment in
    `create_access_token` for why this exists alongside the standard `iat`."""
    return datetime.fromtimestamp(payload["iat_us"] / 1_000_000, tz=UTC)


def expires_at(payload: dict[str, Any]) -> datetime:
    """Second precision is fine here: this only bounds a revocation deny-list
    entry's TTL, where being off by up to a second is harmless."""
    return datetime.fromtimestamp(payload["exp"], tz=UTC)


_TOTP_CHALLENGE_PURPOSE = "totp_challenge"
_TOTP_CHALLENGE_TTL = timedelta(minutes=5)


class InvalidTotpChallengeError(Exception):
    """Not a challenge token this process issued, or it has expired."""


class TotpChallenge(NamedTuple):
    user_id: uuid.UUID
    #: A fresh id per issued token, for `app.core.twofactor.challenge_store`
    #: to key single-use consumption on — deliberately named `cid`, not
    #: `jti`: `decode_access_token` requires both a `jti` *and* an `iat_us`
    #: claim and raises `InvalidTokenError` on anything missing either, so
    #: this token still can never be accepted by `get_current_user` even if
    #: presented as a Bearer token, whatever this claim is called.
    challenge_id: str


def create_totp_challenge_token(*, subject: uuid.UUID) -> str:
    """A short-lived ticket standing in for "the password check already
    passed"; `POST /auth/login/2fa` redeems it once for a real session.

    Deliberately carries no `iat_us` — see `TotpChallenge.challenge_id`'s
    docstring for why that alone keeps this out of `get_current_user`'s
    reach. Its authority is scoped to one purpose by construction, not by a
    check `/auth/login/2fa` could forget.
    """
    settings = get_settings()
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": str(subject),
        "purpose": _TOTP_CHALLENGE_PURPOSE,
        "cid": str(uuid.uuid4()),
        "iat": now,
        "exp": now + _TOTP_CHALLENGE_TTL,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_totp_challenge_token(token: str) -> TotpChallenge:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise InvalidTotpChallengeError(str(exc)) from exc
    if payload.get("purpose") != _TOTP_CHALLENGE_PURPOSE:
        raise InvalidTotpChallengeError("not a totp challenge token")
    try:
        return TotpChallenge(
            user_id=uuid.UUID(str(payload["sub"])), challenge_id=str(payload["cid"])
        )
    except (KeyError, ValueError) as exc:
        raise InvalidTotpChallengeError("missing or invalid claims") from exc
