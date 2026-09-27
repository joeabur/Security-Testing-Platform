from fastapi import APIRouter

from app.api.v1.routers import (
    api_keys,
    assistant,
    auth,
    findings,
    health,
    integrations,
    organizations,
    remediation,
    reports,
    repositories,
    runs,
    surface,
    targets,
    vcs,
    workflows,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(organizations.router)
api_router.include_router(api_keys.router)
api_router.include_router(targets.router)
api_router.include_router(repositories.router)
api_router.include_router(surface.router)
api_router.include_router(runs.router)
api_router.include_router(reports.router)
api_router.include_router(findings.router)
api_router.include_router(remediation.router)
api_router.include_router(integrations.router)
api_router.include_router(vcs.router)
api_router.include_router(assistant.router)
api_router.include_router(workflows.router)
