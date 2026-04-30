# Zomate Fitness Backend

FastAPI + SQLAlchemy 2.x backend for the Zomate Fitness management system. All persistent data goes through PostgreSQL via `DATABASE_URL`.

## Local Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
python scripts/seed.py
uvicorn app.main:app --reload
```

`python run.py` is also available for local development.

## Environment

- `DATABASE_URL`: PostgreSQL connection string.
- `UPLOADS_DIR`: local storage root for photos and receipts, default `./uploads`.
- `ACTIVE_MEMBER_DAYS`: active badge window, default `30`.
- `FRONTEND_ORIGIN`: comma-separated allowed Next.js origins.

Uploads are served from `/uploads/**`. WhatsApp is not connected; resend endpoints return `501`.

## Database

Schema changes are managed by Alembic under `alembic/versions/`.

```bash
alembic upgrade head
python scripts/seed.py
```

The seed script is idempotent and populates baseline branches, coaches, and packages.

## API Docs

Swagger UI: `http://localhost:8000/docs`
ReDoc: `http://localhost:8000/redoc`
Health: `GET /api/health`, readiness: `GET /api/health/db`
