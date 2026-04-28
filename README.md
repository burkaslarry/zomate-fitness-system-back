# Zomate Fitness Backend Demo

FastAPI backend for the local demo of:
- Digital onboarding
- Trial purchase + WhatsApp simulation
- QR+PIN check-in with lesson deduction
- Hikvision FaceID phase-2 simulation

## Local setup

1. Create PostgreSQL database:
   - DB name: `zomate_fitness_system`
2. Copy `.env.example` to `.env` and update credentials if needed.
3. Install and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

API runs at `http://localhost:8000`.

**Swagger UI:** http://localhost:8000/docs · **ReDoc:** http://localhost:8000/redoc · OpenAPI schema: `/openapi.json`. Root `/` redirects to `/docs`.

**Health checks:** `GET /api/health` / `GET /health`（liveness）；`GET /api/health/db` / `GET /health/db`（PostgreSQL readiness）。毋須認證。

## Table naming

All demo tables use the requested prefix:
- `zomate_fs_students`
- `zomate_fs_checkin_logs`
- `zomate_fs_whatsapp_logs`

## Deploy to Render (Docker image)

1. Keep `Dockerfile` and `render.yaml` in this folder.
2. In Render, create a Web Service from this backend directory.
3. Set env var:
   - `DATABASE_URL` (your Render PostgreSQL connection string)
   - `CORS_ALLOWED_ORIGINS` (comma-separated frontend domains)
4. Health check path: `/health`.
5. Refer to `.env.production.example` for production variable format.