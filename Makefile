.PHONY: up down migrate test logs dispatch provision-dispatcher verify

# db first, then the role, then everything else.
#
# `migrate` runs 0018, which refuses to proceed unless app_dispatcher exists --
# and provisioning it needs a running db. A single `docker compose up` asks for
# both at once and fails on a database that predates 0018, because db/init only
# runs on a fresh volume.
#
# provision-dispatcher is idempotent, so running it on every `up` costs a
# subsecond no-op and removes the ordering trap. Note what this does NOT do:
# migrations still cannot create the role. app_owner is NOCREATEROLE, and a
# developer typing `make up` is an operator action in a way that automatic
# deploy-time code is not.
up:
	docker compose up -d --build db
	@echo "waiting for postgres..."
	@until docker compose exec -T db pg_isready -U postgres -d partner_backend >/dev/null 2>&1; do sleep 1; done
	@$(MAKE) --no-print-directory provision-dispatcher
	docker compose up -d --build

down:
	docker compose down -v

migrate:
	docker compose run --rm migrate

test:
	docker compose exec api pytest

logs:
	docker compose logs -f api

# One shot. Runs as app_dispatcher, which can reach three tables and nothing
# else -- see 0018.
dispatch:
	docker compose run --rm dispatcher

# Idempotent. Required once on a database that predates 0018; harmless after.
provision-dispatcher:
	@docker compose exec -T db psql -q -U postgres -d partner_backend \
	  < scripts/provision_dispatcher_role.sql

# The static gates, in the container -- which is what proves the files landed.
verify:
	docker compose exec api python3 verify_fixes.py
	docker compose exec api alembic check
