# Database (Render · eventxp / EventXP)

All application tables use the **`zomate_fs_*`** prefix (see `app/models.py`). SQLAlchemy creates them on startup (`Base.metadata.create_all`).

## Connection string

In Render Dashboard → your PostgreSQL (eventxp) → **External Database URL**, copy the URL.

Set in `.env` (or Render **Environment** for the FastAPI service):

```bash
DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DATABASE
```

The app normalizes `postgres://` → `postgresql+psycopg2://` and enables **`sslmode=require`** when the host looks like Render (or set `DATABASE_SSL=1`).

## Verify

```bash
curl -s http://localhost:8000/api/health
curl -s http://localhost:8000/api/health/db
# 等同路径（无前缀）：
curl -s http://localhost:8000/health
curl -s http://localhost:8000/health/db
```

## CSV import / export

Authoritative CSV endpoints (PostgreSQL-backed):

| Action | Method | Path |
|--------|--------|------|
| Export students | `GET` | `/api/admin/students/export.csv` |
| Import students | `POST` | `/api/admin/students/import` (multipart `file`) |
| Export branches | `GET` | `/api/admin/branches/export.csv` |
| Import branches | `POST` | `/api/admin/branches/import` |
| Export coaches | `GET` | `/api/admin/coaches/export.csv` |
| Import coaches | `POST` | `/api/admin/coaches/import` |
| Attendance CSV template | `GET` | `/api/admin/attendance/template.csv` |

All require `Authorization: Bearer <token>` (ADMIN or CLERK). The Next.js app should set `NEXT_PUBLIC_API_BASE_URL` to this API base and use `downloadCsv` / `uploadCsv` from `lib/api.ts`.

## Frontend + backend（唔用 Next mock）

1. **後端** `zomate-fitness-system-back/`：`DATABASE_URL` = eventxp External URL（見上文）。
2. **前端** `zomate-fitness-system-front/`：設 `NEXT_PUBLIC_API_BASE_URL` 指向該 FastAPI（或本機 dev 可不設，預設 `http://127.0.0.1:8000`）。
3. 不要用 mock 時：**不要**設定 `NEXT_PUBLIC_USE_NEXT_MOCK_API`。全站請求會走 FastAPI → PostgreSQL。

本機一次啟動（遠端 DB）可用專案根目錄：`DATABASE_URL='…' ./run-demo-with-remote-db.sh`
