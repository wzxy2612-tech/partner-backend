from contextlib import asynccontextmanager
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import (auth, partners, workspaces, onboarding, invitations,
                         activity, branding, workflows, usage, maintenance)
from app.services.outbox_crypto import validate_outbox_config


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Resolve the outbox key configuration before serving anything.

    The keyring is read lazily on every encrypt, so a missing or inconsistent
    configuration would otherwise surface as a 500 on someone's first CSV
    onboarding rather than as a container that refuses to start. A deployment
    error should be visible to the deployment.
    """
    validate_outbox_config()
    yield


app = FastAPI(title="Partner Multi-Tenancy Backend", version="0.5.0",
              lifespan=lifespan)

# Local frontend development only, and the list is a literal.
#
# `allow_origins=["*"]` cannot be combined with credentials by spec, so the
# usual next step is a regex or an echo of the Origin header -- at which point
# any site can call this API with a victim's Authorization header attached. A
# hardcoded list has no such next step.
#
# Read from an env var with NO default rather than being unconditional: a
# deployment that has not named its origins gets no CORS at all, which is the
# safe direction. Same shape as OUTBOX_SENDER: absent means refuse, not guess.
#
# This sits below the lifespan gate and does not touch it. Adding middleware is
# inside the freeze boundary; changing what lifespan calls, or when, is not.
CORS_ORIGINS_ENV = "CORS_ALLOW_ORIGINS"
_origins = [o.strip() for o in os.environ.get(CORS_ORIGINS_ENV, "").split(",")
            if o.strip()]
if _origins:
    if "*" in _origins:
        raise RuntimeError(
            f"{CORS_ORIGINS_ENV} must name origins literally. A wildcard here "
            f"would let any site issue credentialed requests against this API.")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=True,
        # Authorization on a cross-origin request always triggers a preflight,
        # and FastAPI's routes do not answer OPTIONS -- the middleware does.
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

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
