from fastapi import FastAPI

from app.routers import auth, partners, workspaces

app = FastAPI(title="Partner Multi-Tenancy Backend", version="0.2.0")

app.include_router(auth.router)
app.include_router(partners.router)
app.include_router(workspaces.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/")
def root() -> dict:
    return {
        "service": "partner-multitenancy-backend",
        "phase": 2,
        "implemented": [
            "three-role DB privilege model",
            "RLS tenant isolation (fail closed)",
            "safe additive partner migration",
            "auth: revocable sessions + server-resolved principal",
            "partner activation / suspension (+ cascade token revocation)",
            "domain deactivation",
            "workspace parent/child tree (RLS-isolated)",
            "scope inheritance rule",
            "Stripe-bypass decision",
        ],
        "next": [
            "server-side RBAC guards on every mutation (Phase 3)",
            "two-step transactional CSV onboarding (Phase 3)",
            "activity-log API with pagination + filters (Phase 4)",
            "branding inheritance + billing-contact API (Phase 4)",
        ],
    }
