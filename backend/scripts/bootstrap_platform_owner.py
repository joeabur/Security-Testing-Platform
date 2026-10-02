"""Grant the first platform owner — a one-time deployment-setup step.

`User.platform_role` (app/models/user.py) is authority over the deployment
itself, above every organization's own `Role.OWNER`. Nothing grants it
automatically: a fresh deployment has zero platform owners until an operator
runs this script, once, after the account that should hold it has already
registered through the normal `/auth/register` flow.

This is deliberately *not* something the application does for itself at
startup. An auto-grant tied to `settings.platform_owner_bootstrap_email`
checked on every boot would mean the bootstrap email itself is a standing
piece of authorization logic — exactly the "hard-coded address" shape this
whole feature exists to avoid (see app/api/v1/routers/platform.py's module
docstring). Run once, by a human, this script instead reads that setting a
single time, finds the one already-registered account it names, and never
looks at it again: every owner after the first is granted by an existing
owner through `POST /platform/owners`, not by this script or that setting.

Refuses outright, rather than adding a second owner, if a platform owner
already exists — re-running this after bootstrap is a mistake to catch, not
a second grant to make quietly. Use `POST /platform/owners` for that,
explicitly, as an existing owner.

Usage: `python -m scripts.bootstrap_platform_owner` (from `backend/`), with
`KERVY_PLATFORM_OWNER_BOOTSTRAP_EMAIL` set to the already-registered
account's email.
"""

from __future__ import annotations

import asyncio
import sys

from sqlalchemy import func, select

from app.audit.service import record_event
from app.core.config import get_settings
from app.db.session import get_session_factory
from app.models.user import PlatformRole, User


async def _bootstrap() -> int:
    settings = get_settings()
    email = settings.platform_owner_bootstrap_email
    if not email:
        print(
            "KERVY_PLATFORM_OWNER_BOOTSTRAP_EMAIL is not set — nothing to do.",
            file=sys.stderr,
        )
        return 1

    session_factory = get_session_factory()
    async with session_factory() as db:
        existing_count = (
            await db.execute(
                select(func.count(User.id)).where(User.platform_role == PlatformRole.OWNER)
            )
        ).scalar_one()
        if existing_count > 0:
            print(
                f"A platform owner already exists ({existing_count}). Refusing to "
                "bootstrap a second one — grant one through POST /platform/owners "
                "as an existing owner instead.",
                file=sys.stderr,
            )
            return 1

        user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if user is None:
            print(
                f"No registered user with email {email!r}. Register that account "
                "through POST /api/v1/auth/register first, then re-run this script.",
                file=sys.stderr,
            )
            return 1

        user.platform_role = PlatformRole.OWNER
        await db.flush()
        await record_event(
            db,
            action="platform_owner.bootstrap",
            resource_type="user",
            resource_id=str(user.id),
            result="allow",
            user_id=user.id,
            metadata={"email": user.email},
        )
        await db.commit()

    print(f"Granted platform-owner authority to {email}.")
    return 0


def main() -> int:
    return asyncio.run(_bootstrap())


if __name__ == "__main__":
    sys.exit(main())
