from fastapi import FastAPI

from app.routers import (auth, partners, workspaces, onboarding, invitations,
                         activity, branding, workflows, usage, maintenance)

app = FastAPI(title="Partner Multi-Tenancy Backend", version="0.5.0")

app.include_router(auth.router)
app.include_router(partners.router)
app.include_router(workspaces.router)
app.include_router(onboarding.router)
app.include_router(invitations.router)
app.include_router(activity.router)
app.include_router(branding.router)
app.include_router(workflows.router)
app.include_router(usage.router)
app.include_router(maintenance.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/")
def root() -> dict:
    return {
        "service": "partner-multitenancy-backend",
        "phase": 5,
        "implemented": [
            "three-role DB privilege model + RLS tenant isolation (fail closed)",
            "auth: revocable sessions + server-resolved principal",
            "partner activation / suspension / domain deactivation",
            "workspace parent/child tree (RLS-isolated)",
            "server-side RBAC (role x scope) on mutations",
            "two-step transactional CSV onboarding + invitations",
            "activity-log API (keyset pagination + date/event filters)",
            "parent-hub branding inheritance + billing-contact controls",
            "workflow-template cloning gated by connector verification",
            "monthly token-usage tracking",
            "60-day suspension purge + 1-year thread archival jobs",
        ],
        "next": ["hardening, docs, and deployment"],
    }
