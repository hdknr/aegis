.PHONY: test test-unit test-e2e smoke build up down docs

test: test-unit

test-unit:
	uv run pytest tests/ -v --ignore=tests/e2e

test-e2e:
	./scripts/test-e2e.sh

build:
	docker compose build

smoke:
	./scripts/smoke-test.sh

up:
	docker compose up -d
	@echo ""
	@echo "Running smoke test..."
	@./scripts/smoke-test.sh

down:
	docker compose down -v

docs:
	uv run mkdocs serve
