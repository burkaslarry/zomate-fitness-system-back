# Zomate Fitness Backend

FastAPI + SQLAlchemy 2.x backend for the Zomate Fitness management system. All persistent data goes through PostgreSQL via `DATABASE_URL`.

## Local Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
python scripts/seed_phase1.py
uvicorn app.main:app --reload
```

`python run.py` is also available for local development.

## Environment

- `DATABASE_URL`: PostgreSQL connection string.
- `UPLOADS_DIR`: local storage root for photos and receipts, default `./uploads`.
- `ACTIVE_MEMBER_DAYS`: active badge window, default `30`.
- `FRONTEND_ORIGIN`: comma-separated allowed Next.js origins.
- `PUBLIC_BASE_URL`: public backend URL for keepalive self-ping.
- `KEEPALIVE_ENABLED`: set `true` on Render if the service should self-ping `/api/health`.
- `REGISTER_OTP_MOCK_CODE`: optional fixed registration OTP for local verification.

Uploads are served from `/uploads/**`. WhatsApp/SMS integrations are mocked in dev. The OTP adapter has a `TODO(Twilio)` seam in `app/otp_sms.py` for a future Twilio Verify / SMS provider.

## Database

Schema changes are managed by Alembic under `alembic/versions/`.

```bash
alembic upgrade head
python scripts/seed_phase1.py
```

The seed script is idempotent and populates the Phase-1 course categories:

- 新學生一對一
- 新學生一對二
- 續會學生一對一
- 續會學生一對二
- 自帶學生一對一
- 自帶學生一對二

Course categories use `is_deleted` for soft delete / hide-show. Default is visible (`is_deleted=false`).

## Feature codes (`Features Fxxx:… -- …`)

Module headers and `app/main.py` use block comments linking behavior to shorthand codes:

| Code | Scope |
|------|-------|
| F001 | `app/health_app.py` — liveness payload for `/health` and `/api/health` |
| F002 | `app/logutil.py` — structured JSON-ish log lines + `instance_id` |
| F003 | `app/config.py` — `Settings` from env (.env / Render) |
| F004 | `app/keepalive.py` — optional self-ping to `PUBLIC_BASE_URL` |
| F005 | `app/timezone.py` — Asia/Hong_Kong wall-clock for attendance dates |
| F006 | `app/otp_sms.py` — OTP provider seam (mock; Twilio TODO) |
| F007 | `app/register_public.py`, `app/pin_util.py` — QR/member OTP + hashed PIN |
| F008–F014 | Implemented in `app/main.py` — staff onboarding, courses/PINs, check-in ledger, categories, finance reports |
| F015 | `components/backend-shell.tsx` (frontend repo) — admin chrome / navigation |
| F016 | `scripts/verify_f01_f04.py` — HTTP regression harness for stories F01–F04 |

Product verification stories **F01–F04** (scripts and pytest) intentionally stay separate from the **F001+** engineering codes above.

## API Docs

Swagger UI: `http://localhost:8000/docs`
ReDoc: `http://localhost:8000/redoc`
Health: `GET /api/health`, readiness: `GET /api/health/db`

## Core Feature Verification (F01-F04)

Run these after setting `DATABASE_URL` and applying migrations:

```bash
# Unit and integration slices
pytest tests/ -q

# End-to-end API story against a running backend
python3 ../scripts/verify_f01_f04.py http://127.0.0.1:8000
```

The F01-F04 verifier creates unique test data and checks:

- **F01 onboarding**: `POST /api/v1/students/register`, policy/PAR-Q payload, public student search.
- **F02 trial/course**: `POST /api/trial-purchase`, course creation, class PIN allocation, category enrollment with installments.
- **F03 QR check-in**: `POST /api/checkin` using a **course-specific class PIN** and duplicate check-in rejection.
- **F04 finance**: sales report, expense entry, coach attendance report, session ledger response.

## Operational Notes

- Student account PIN is legacy display only; check-in now uses **one class PIN per course enrollment**.
- Coach/admin trial quota is stored on the student as `coach_trial_quota_remaining` and defaults to `1`.
- Keepalive liveness uses `/api/health`; readiness with DB remains `/api/health/db`.
