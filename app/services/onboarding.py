"""Two-step CSV onboarding.

Step 1 -- validate(): parse the CSV, check every row, return per-row errors.
         WRITES NOTHING. The caller shows the report; the user fixes and retries.
Step 2 -- provision(): only runs on a clean report, and does ALL inserts inside a
         single SAVEPOINT. Any failure rolls the whole batch back -- never a
         half-onboarded partner.

Both run under the caller's partner RLS scope, so company/email lookups and every
insert are automatically confined to that partner (and RLS re-checks partner_id
on write).
"""
import csv
import io
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from app.auth.tokens import new_token, hash_token
from app.auth.password import hash_password
from app.models.enums import Role
from app.services import outbox
from app.services.activity import record

EXPECTED_COLUMNS = ["email", "name", "role", "company"]
ALLOWED_ROLES = {Role.company_admin, Role.author, Role.read_only}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
INVITE_TTL = timedelta(days=14)


@dataclass
class RowReport:
    row: int
    email: str | None
    errors: list[str]
    # resolved values, populated only when the row is valid
    name: str = ""
    role: Role | None = None
    company_id: UUID | None = None

    @property
    def valid(self) -> bool:
        return not self.errors


@dataclass
class ValidationReport:
    rows: list[RowReport] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return any(not r.valid for r in self.rows)

    @property
    def valid_rows(self) -> list[RowReport]:
        return [r for r in self.rows if r.valid]

    def as_dict(self) -> dict:
        return {
            "total": len(self.rows),
            "valid": len(self.valid_rows),
            "has_errors": self.has_errors,
            "rows": [{"row": r.row, "email": r.email, "errors": r.errors} for r in self.rows],
        }


def parse_csv(raw: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(raw))
    return [{(k or "").strip().lower(): (v or "").strip() for k, v in row.items()} for row in reader]


# Emails are globally unique (users.email UNIQUE, from the 0001 baseline), but
# the partner path can only SEE its own tenant. So validate used to pass a row
# whose email already belonged to another partner -- or to a direct customer --
# and the conflict only surfaced as an IntegrityError at INSERT time, after the
# batch had already started and (until the outbox round) after mail had gone out.
#
# The check therefore has to run somewhere the whole table is visible, i.e. the
# platform path. That immediately creates a second problem: an endpoint that
# reports "this email exists" across tenants is an enumeration oracle -- partner
# A could probe for partner B's customers one address at a time.
#
# The narrowing is: this returns ONLY the subset of the asked-about addresses
# that are taken, and nothing about WHO holds them. The caller already knows the
# addresses (it supplied them), so the only new information is a boolean per
# address -- the minimum needed to report a row error at all. Which tenant, or
# whether it is a direct customer, never leaves this function.
def taken_emails(pdb: OrmSession, emails: set[str]) -> set[str]:
    """Which of these addresses already exist, system-wide. Booleans only.

    Takes the platform session as an argument rather than opening one. An
    earlier cut had validate() open its own platform_session internally, which
    meant a read-only precheck quietly held a second connection -- and, on the
    commit path, opened it inside the caller's business transaction and
    COMMITTED it on exit. Passing the session in keeps the connection lifetime
    with whoever owns the request, and makes validate() testable without a pool.
    """
    if not emails:
        return set()
    return {e.lower() for (e,) in pdb.execute(
        text("SELECT email FROM users WHERE lower(email) = ANY(:list)"),
        {"list": sorted(emails)})}


def validate(db: OrmSession, rows: list[dict],
             globally_taken: set[str] | None = None) -> ValidationReport:
    # RLS scopes both lookups to the caller's partner.
    companies = {name.lower(): cid
                 for cid, name in db.execute(text("SELECT id, name FROM companies"))}
    existing = {e.lower() for (e,) in db.execute(text("SELECT email FROM users"))}
    # Cross-tenant existence, resolved by the caller on the platform path.
    # Defaults to empty so the partner-visible checks still work standalone;
    # the router always supplies it.
    globally_taken = globally_taken or set()

    seen: set[str] = set()
    report = ValidationReport()
    for i, row in enumerate(rows, start=1):
        errors: list[str] = []
        email = (row.get("email") or "").lower()
        name = row.get("name") or ""
        role_s = row.get("role") or ""
        company_s = row.get("company") or ""

        if not email or not EMAIL_RE.match(email):
            errors.append("invalid or missing email")
        if not name:
            errors.append("missing name")

        try:
            role = Role(role_s)
        except ValueError:
            role = None
        if role not in ALLOWED_ROLES:
            errors.append(f"invalid role '{role_s}' (allowed: company_admin, author, read_only)")
            role = None

        company_id = companies.get(company_s.lower())
        if not company_s:
            errors.append("missing company")
        elif company_id is None:
            errors.append(f"unknown company '{company_s}'")

        if email:
            if email in seen:
                errors.append("duplicate email within file")
            elif email in existing or email in globally_taken:
                # Deliberately identical wording whether the address belongs to
                # this partner, another partner, or a direct customer. The
                # caller learns that it cannot use the address, which is all it
                # needs, and nothing about who holds it.
                errors.append("email already registered")
            seen.add(email)

        report.rows.append(RowReport(row=i, email=email or None, errors=errors,
                                     name=name, role=role, company_id=company_id))
    return report


# The unique index behind users.email. Created inline as `unique=True` in the
# 0001 baseline, so PostgreSQL generated the name.
EMAIL_UNIQUE_CONSTRAINT = "users_email_key"


def _is_email_conflict(exc: IntegrityError) -> bool:
    """True only for a violation of users.email uniqueness.

    Matches on the CONSTRAINT NAME from the driver's structured diagnostics, not
    on the message text: message wording varies with server version and locale,
    and a substring match on 'email' would also catch a future constraint that
    merely mentions the column. The name is the identifier the schema actually
    declares.
    """
    diag = getattr(getattr(exc, "orig", None), "diag", None)
    return getattr(diag, "constraint_name", None) == EMAIL_UNIQUE_CONSTRAINT


class EmailAlreadyRegistered(Exception):
    """A row's email was taken between validate and INSERT.

    The precheck narrows the window; it cannot close it. Two concurrent
    onboardings can both see an address as free and both try to claim it, and
    the database decides. This is the fail-closed backstop that turns the
    resulting unique violation into a stable 409 instead of a 500.

    Carries the address the CALLER supplied -- which the caller already knows --
    and nothing about the existing holder.
    """
    def __init__(self, email: str):
        self.email = email
        super().__init__(f"email already registered: {email}")


@dataclass
class ProvisionResult:
    created_user_ids: list[UUID] = field(default_factory=list)


def provision(db: OrmSession, partner_id: UUID,
              report: ValidationReport) -> ProvisionResult:
    """Insert every valid row's user + membership + invitation atomically, and
    record one outbox event per invitation.

    The SAVEPOINT means a failure on any row discards the entire batch --
    including the outbox events, so a discarded batch sends nothing.

    No `sender` parameter any more, and that is the point: this function cannot
    send mail, so it cannot produce a side effect the rollback is unable to
    undo. Delivery is outbox.dispatch_pending(), run after the commit.
    """
    result = ProvisionResult()
    now = datetime.now(timezone.utc)
    with db.begin_nested():  # SAVEPOINT: all-or-nothing for the batch
        for r in report.valid_rows:
            user_id = uuid4()
            try:
                db.execute(text(
                    "INSERT INTO users (id, email, name, partner_id, billing_source, is_active) "
                    "VALUES (:id, :email, :name, :pid, 'partner', false)"),
                    {"id": str(user_id), "email": r.email, "name": r.name,
                     "pid": str(partner_id)})
            except IntegrityError as exc:
                # Only the email uniqueness violation is reinterpreted. Any other
                # constraint failure is a real bug and must keep propagating --
                # catching IntegrityError broadly would quietly turn the tenant
                # composite FKs from 0007 into "409 conflict" as well.
                if _is_email_conflict(exc):
                    raise EmailAlreadyRegistered(r.email) from exc
                raise
            db.execute(text(
                "INSERT INTO memberships (user_id, partner_id, scope_type, scope_id, role) "
                "VALUES (:uid, :pid, 'company', :cid, :role)"),
                {"uid": str(user_id), "pid": str(partner_id),
                 "cid": str(r.company_id), "role": r.role.value})
            token = new_token()
            invitation_id = db.execute(text(
                "INSERT INTO invitations (partner_id, user_id, email, token_hash, expires_at) "
                "VALUES (:pid, :uid, :email, :h, :exp) RETURNING id"),
                {"pid": str(partner_id), "uid": str(user_id), "email": r.email,
                 "h": hash_token(token), "exp": now + INVITE_TTL}).scalar_one()

            # The intent to mail is recorded in THIS transaction, next to the
            # invitation it belongs to. Nothing is sent here.
            #
            # This line used to be sender.send_invitation(...), inside the
            # SAVEPOINT. A failure on any later row rolled back every user and
            # invitation -- but the mail already sent could not be recalled, so
            # earlier recipients held tokens for records that no longer existed.
            # "All or nothing" was only true of the half of the world the
            # transaction controls.
            outbox.enqueue_invitation(
                db, partner_id=partner_id, invitation_id=invitation_id,
                recipient=r.email, token=token)
            result.created_user_ids.append(user_id)
    return result


def onboard(db: OrmSession, partner_id: UUID, raw_csv: str,
            globally_taken: set[str] | None = None) -> tuple[ValidationReport, ProvisionResult | None]:
    """Validate then, only if clean, provision. Returns (report, result|None)."""
    rows = parse_csv(raw_csv)
    report = validate(db, rows, globally_taken)
    if report.has_errors:
        return report, None
    result = provision(db, partner_id, report)
    record(db, partner_id, "partner.users_onboarded",
           payload={"count": len(result.created_user_ids)})
    return report, result


def accept_invitation(db: OrmSession, token: str, password: str) -> bool:
    """Redeem an invitation: set the user's password, activate them, mark accepted.
    Returns False if the token is unknown, already used, expired, or belongs to a
    partner that is not currently active.

    The status transition IS the claim. This used to SELECT the invitation,
    decide it was pending, then unconditionally UPDATE -- so two concurrent
    redemptions of a one-time invite could both observe `pending` and both
    proceed, leaving whichever password landed second. A single conditional
    UPDATE moves the decision into the row lock: exactly one caller can see a
    row transition out of `pending`, and only that caller gets a returned row.

    The partner check was missing from that claim, and this path runs on the
    platform connection, which is BYPASSRLS -- so the active-state gate that
    twelve policies enforce does not exist here. Reported live: suspend a
    partner, redeem an old token, and the user is activated; reactivate the
    partner later and they can log in. The gate has to be spelled out on this
    side, because RLS is precisely what this side does not have.

    There is deliberately no condition on `users.is_active`. An invited user is
    inactive from creation until redemption, so that flag cannot distinguish
    "not yet redeemed" from "revoked" -- reading it as the latter would refuse
    every legitimate redemption. The invitation's own status carries that fact,
    which is why the lifecycle transitions revoke invitations rather than
    relying on the user row to imply it.

    And that is also what orders this against a concurrent suspension, with no
    explicit lock needed. An earlier version took FOR SHARE on the partner row
    first, out of worry about how PostgreSQL re-evaluates a WHERE clause
    containing a function over a DIFFERENT table when an UPDATE unblocks. But
    suspension revokes the invitation in the same transaction, so the deciding
    predicate is `status = 'pending'` -- a column on the very row being locked,
    which is exactly the case re-evaluation handles unambiguously. The partner
    check is depth, not the mechanism.

    The lock was not merely redundant. SELECT ... FOR SHARE requires UPDATE
    privilege on the table, which app_runtime held only through 0011's
    column-level grant on billing_contact_email -- the grant 0015 removes. It
    would have been a lock whose legality depended on a privilege the same
    revision took away.
    """
    claimed = db.execute(text(
        "UPDATE invitations SET status = 'accepted', accepted_at = now() "
        "WHERE token_hash = :h AND status = 'pending' AND expires_at > now() "
        "  AND public.partner_is_active(partner_id) "
        "RETURNING user_id"),
        {"h": hash_token(token)}).first()
    if claimed is None:
        return False
    db.execute(text("UPDATE users SET hashed_password = :pw, is_active = true WHERE id = :u"),
               {"pw": hash_password(password), "u": str(claimed.user_id)})
    return True
