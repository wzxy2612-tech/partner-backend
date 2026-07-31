.PHONY: up down migrate test logs
up:
	docker compose up -d --build
down:
	docker compose down -v
migrate:
	docker compose exec api alembic upgrade head
test:
	docker compose exec api pytest
logs:
	docker compose logs -f api
