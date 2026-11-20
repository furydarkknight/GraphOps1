.PHONY: up down seed eval test lint build

## ── Docker ──────────────────────────────────────────────────────────────────

up:
	docker compose up --build

up-dev:
	docker compose -f docker-compose.yml -f docker-compose.override.yml up --build

down:
	docker compose down -v

## ── Seed demo data ───────────────────────────────────────────────────────────

seed:
	@echo "Running Prisma seed..."
	cd api && npx prisma db push && npx tsx prisma/seed.ts
	@echo "Generating synthetic demo graph..."
	cd analytics && python -m app.synthetic.generator --size 1000 --seed 42 --output demo_1k.json
	@echo "Seed complete."

## ── Evaluation harness ───────────────────────────────────────────────────────

eval:
	@echo "Running evaluation harness..."
	cd analytics && python eval/run_eval.py --sizes 1000 10000 --output ../eval/results/results
	@echo "Results written to eval/results/results.{md,json}"

## ── Tests ────────────────────────────────────────────────────────────────────

test: test-ts test-py

test-ts:
	@echo "Running TypeScript unit tests..."
	cd api && npm test
	@echo "Running TypeScript integration tests..."
	cd tests && npm test

test-py:
	@echo "Running Python tests..."
	cd analytics && python -m pytest tests/python -v

## ── Lint & typecheck ─────────────────────────────────────────────────────────

lint:
	cd api && npm run lint
	cd client && npm run lint
	cd analytics && python -m ruff check app/ tests/

typecheck:
	cd api && npm run typecheck
	cd client && npm run typecheck

## ── Build ────────────────────────────────────────────────────────────────────

build:
	cd client && npm run build
	cd api && npm run build

## ── Dev (without Docker) ─────────────────────────────────────────────────────

dev-api:
	cd api && npm run dev

dev-analytics:
	cd analytics && uvicorn app.main:app --reload --port 8000

dev-client:
	cd client && npm run dev

## ── Helpers ──────────────────────────────────────────────────────────────────

migrate:
	cd api && npx prisma migrate dev

generate:
	cd api && npx prisma generate
