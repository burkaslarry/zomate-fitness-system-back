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

## [F005][S003] WhatsApp templates / WhatsApp 範本

Use the root README traceability matrix for this integration. The automated sender is **+852 9756 8105** (Phone Number ID `1292795760587834`, WABA `1623067752857830`). Store the System User token only in server environment variables.

系統通知用 **9756 8105**；人手查詢維持 **6052 9291**。以下四款 `zh_HK` / `UTILITY` 範本於 2026-10-13 獲 Meta 批准：

| Internal key | Meta template | Body variables |
|---|---|---:|
| `payment_student_pending` | `zomate_payment_pending` | 7 |
| `payment_student_installment` | `zomate_payment_installment` | 12 |
| `payment_student_full` | `zomate_payment_full` | 10 |
| `payment_coach` | `zomate_payment_coach` | 11 |

Merge these mappings into `WHATSAPP_TEMPLATE_MAP` and preserve `booking_confirmation`. The root artifact `output/whatsapp-templates/template-map.json` contains the exact ordered context fields. `next_lesson_date` currently means the enrollment start date, so the Meta wording is 課程開始日期. `amount_paid` is labeled 付款記錄金額 because the current receipt context may represent one payment rather than a cumulative total. Empty values render as `—`; multiline notes are flattened for Meta.

Quick check / 快速驗證：log in as `masterzoe`, then POST `/api/admin/whatsapp/test-send` with `phone`, `template_name`, `language_code`, and ordered `body_parameters`. Only username `masterzoe` with role `ADMIN` or `MASTER_ADMIN` may call this test endpoint; other authenticated users receive 403 and anonymous callers receive 401. This restriction applies to test sends; existing business notification permissions remain separate.

Run `python -m pytest tests/ -q` in the project virtual environment. Test database fixtures use isolated SQLite, never production PostgreSQL. Template-send tests verify authentication, recipient normalization, variable order, and whitespace handling without contacting Meta.

### Trigger rules / 實際觸發

`POST /api/renewals`, member/staff receipt upload, and `/api/admin/students/{student_id}/send-payment-reminder` invoke `send_payment_whatsapp_notifications`. Coach receipt upload uses the same helper with `notify_coach=false`. Receipt uploads respect `send_whatsapp`; student consent is checked by `log_whatsapp`.

| Condition | Internal template key |
|---|---|
| `receipt_confirmed=false` | `payment_student_pending` |
| `receipt_confirmed=true`, installment recognized | `payment_student_installment` |
| `receipt_confirmed=true`, no installment recognized | `payment_student_full` |
| Notifications enabled, `notify_coach=true`, matching enrollment/coach/phone present | Additional `payment_coach` |

Receipt upload sets `receipt_confirmed=true` immediately; it does not wait for independent finance approval. The registration wizard calls `/api/renewals` before creating the new enrollment, so initial notifications may use a previous enrollment or lack the new PIN/installment state. Do not treat these four send tests as acceptance of enrollment association or monetary calculations. These templates have no daily/check-in scheduler; installment notes are message text only.

以上係現時程式行為，唔係「會計確認後先發」嘅承諾。上傳收據預設可即時發學生／教練通知；教練自行上傳只發學生版。正式報 Course 流程仍須驗收新課程、PIN、分期及金額。發送測試只限 masterzoe，正常業務通知沿用原權限。

Release `c4368e206466a59729f4d11ed37f409f0f67ab42` was pushed and deployed Live on Render on 2026-10-13. All 50 tests passed and requirements audit was clean. All four test calls returned `ok=true`, `dry_run=false` and message IDs; the user confirmed all four handset deliveries. Synthetic test bodies did not create real payment records. Course title remains a dynamic context parameter, not a fixed test label.

<!--
Repository maintenance: GitHub remotes use the burkaslarry-GitHub SSH alias,
which selects this account's SSH key and connects over port 443.
-->

### [F003][S003] 簽到通知範本選擇（2026-10-13 更新）

依使用者指定，沿用 `zomate_payment_pending`、`zomate_payment_installment`、`zomate_payment_full`、`zomate_payment_coach` 四款已批准原文；只注入動態資料，不更改固定字眼。額外 `zomate_checkin_student`／`zomate_checkin_coach` 已從正式 Render 映射移除，簽到暫不透過這兩款發送。簽到是否沿用付款四款，待使用者確認；確認前不得聲稱兩款額外簽到通知正在發送。香港電話預設 +852 的處理保留。原有預約確認是獨立既有功能。

The four approved payment wordings remain unchanged. Additional check-in mappings are disabled. Reusing the payment wording on check-in requires the user's choice because those bodies describe receipt/payment status rather than a check-in acknowledgement.
