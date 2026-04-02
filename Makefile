# Makefile — CTI Platform v2.0
# Run from the project root (where docker-compose.yml lives)

.PHONY: help up down logs build shell-backend shell-db \
        seed embed-assets load-samples stats poll \
        migrate dev-backend dev-frontend dev

# ─── Help ─────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  CTI Platform v2.0 — Make targets"
	@echo "  ─────────────────────────────────────────────────────────────────"
	@echo ""
	@echo "  Docker (production-like):"
	@echo "    make up              Start all containers"
	@echo "    make down            Stop all containers"
	@echo "    make build           Rebuild images"
	@echo "    make logs            Follow all container logs"
	@echo "    make logs-worker     Follow Celery worker logs only"
	@echo ""
	@echo "  Database:"
	@echo "    make migrate         Run Alembic migrations"
	@echo "    make seed            Seed demo clients and assets"
	@echo "    make shell-db        Open psql shell"
	@echo ""
	@echo "  Data management:"
	@echo "    make embed-assets    Compute embeddings for all assets"
	@echo "    make load-samples DIR=./my-reports   Bulk-index sample reports"
	@echo "    make stats           Print system statistics"
	@echo "    make poll SOURCE=all Trigger CVE feed poll"
	@echo ""
	@echo "  Development:"
	@echo "    make dev             Start infra + backend + frontend (3 terminals)"
	@echo "    make dev-backend     Start backend only (requires infra running)"
	@echo "    make dev-frontend    Start frontend dev server"
	@echo "    make shell-backend   Open shell in backend container"
	@echo ""

# ─── Docker ───────────────────────────────────────────────────────────────────
up:
	docker compose up -d
	@echo "\n  Frontend:  http://localhost:5173"
	@echo "  API:       http://localhost:8000"
	@echo "  API Docs:  http://localhost:8000/docs\n"

down:
	docker compose down

build:
	docker compose build --no-cache

logs:
	docker compose logs -f

logs-worker:
	docker compose logs -f worker beat

shell-backend:
	docker compose exec backend bash

shell-db:
	docker compose exec postgres psql -U cti -d ctidb

# ─── Database ─────────────────────────────────────────────────────────────────
migrate:
	docker compose exec backend alembic upgrade head

# ─── Data management (runs inside the backend container) ──────────────────────
seed:
	docker compose exec backend python scripts/manage.py seed-clients

embed-assets:
	docker compose exec backend python scripts/manage.py embed-assets

load-samples:
	@if [ -z "$(DIR)" ]; then echo "Usage: make load-samples DIR=./path/to/reports"; exit 1; fi
	docker compose cp $(DIR) backend:/app/import_samples
	docker compose exec backend python scripts/manage.py load-samples /app/import_samples

stats:
	docker compose exec backend python scripts/manage.py stats

poll:
	docker compose exec backend python scripts/manage.py poll $(or $(SOURCE),all)

# ─── Development (local, no Docker for app code) ──────────────────────────────
# Start infra first: make up-infra
up-infra:
	docker compose up -d postgres redis chromadb

dev-backend:
	cd backend && \
	  source venv/bin/activate && \
	  uvicorn main:app --reload --port 8000

dev-worker:
	cd backend && \
	  source venv/bin/activate && \
	  celery -A workers.celery_app worker --loglevel=info -Q cti_feeds,reports,default

dev-beat:
	cd backend && \
	  source venv/bin/activate && \
	  celery -A workers.celery_app beat --loglevel=info

dev-frontend:
	cd frontend && npm run dev

# Setup local Python venv
venv:
	cd backend && \
	  python3 -m venv venv && \
	  source venv/bin/activate && \
	  pip install --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.txt
	@echo "\nVenv ready. Activate with: source backend/venv/bin/activate"

# ─── Utility ──────────────────────────────────────────────────────────────────
clean:
	docker compose down -v
	@echo "All containers and volumes removed"

reset-db:
	docker compose exec postgres psql -U cti -d ctidb -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	docker compose exec backend alembic upgrade head
	@echo "Database reset complete"
