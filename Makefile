.PHONY: install test test-integration lint fmt certs up down doctor clean

install:
	uv sync --extra dev

test:
	uv run pytest -m "not integration"

# Needs Docker. Starts the broker, runs tests that talk to it.
test-integration: up
	BBIOT_INTEGRATION=1 uv run pytest -m integration

lint:
	uv run ruff check .
	uv run ruff format --check .

fmt:
	uv run ruff check --fix .
	uv run ruff format .

certs:
	uv run bbiot tls init

up:
	docker compose up -d --build --wait broker

down:
	docker compose down

doctor:
	uv run bbiot doctor

clean:
	docker compose down -v
	rm -rf .pytest_cache .ruff_cache
