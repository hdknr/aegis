.PHONY: test test-unit test-e2e build up down docs

test: test-unit

test-unit:
	uv run pytest tests/ -v --ignore=tests/e2e

test-e2e:
	./scripts/test-e2e.sh

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down -v

docs:
	uv run mkdocs serve
