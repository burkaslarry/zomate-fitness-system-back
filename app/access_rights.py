"""
[F007][S003]
Feature: Access Rights (Excel matrix)
Step: Role × feature permission map from ``zomate pt management system.xlsx``
Logic: MASTER_ADMIN (Masteradmin), COACH (PT), CLERK (clerk).
"""

from __future__ import annotations

from typing import Literal

AccessRole = Literal["MASTER_ADMIN", "CLERK", "COACH"]

MASTER_ADMIN_USERNAMES: frozenset[str] = frozenset({"masterzoe", "masterfung"})

# Source: /Users/larrylo/Downloads/zomate pt management system.xlsx — 工作表1
ACCESS_FEATURES: list[dict] = [
    {
        "key": "register_new_member",
        "label_zh": "加新會員",
        "href": "/register",
        "roles": ("MASTER_ADMIN", "COACH", "CLERK"),
        "remark": "正常都係掃QR Code 入哩頁？",
    },
    {
        "key": "register_course",
        "label_zh": "加會員報堂",
        "href": "/regCourse",
        "roles": ("MASTER_ADMIN", "COACH", "CLERK"),
        "remark": None,
    },
    {
        "key": "student_list",
        "label_zh": "學生名單",
        "href": "/admin/students",
        "roles": ("MASTER_ADMIN", "COACH", "CLERK"),
        "remark": "教練應該淨係睇到自己學生",
    },
    {
        "key": "coaches",
        "label_zh": "教練",
        "href": "/admin/coaches",
        "roles": ("MASTER_ADMIN",),
        "remark": None,
    },
    {
        "key": "branches",
        "label_zh": "分店管理",
        "href": "/admin/branches",
        "roles": ("MASTER_ADMIN",),
        "remark": None,
    },
    {
        "key": "coach_schedule_checkin",
        "label_zh": "教練日程 · 簽到",
        "href": "/coach/calendar",
        "roles": ("MASTER_ADMIN", "COACH", "CLERK"),
        "remark": "教練應該淨係睇到自己CALENDER",
    },
    {
        "key": "coach_sessions",
        "label_zh": "教練課表",
        "href": "/coach",
        "roles": ("MASTER_ADMIN",),
        "remark": None,
    },
    {
        "key": "qr_checkin_console",
        "label_zh": "QR 簽到中心",
        "href": "/admin/attendance/qr-console",
        "roles": ("MASTER_ADMIN",),
        "remark": None,
    },
    {
        "key": "session_ledger",
        "label_zh": "Session Ledger · 扣堂原因",
        "href": "/admin/students",
        "roles": ("MASTER_ADMIN",),
        "remark": None,
    },
    {
        "key": "student_portal",
        "label_zh": "學生入口",
        "href": "/student",
        "roles": ("MASTER_ADMIN",),
        "remark": None,
    },
    {
        "key": "finance_sales",
        "label_zh": "銷售與分期",
        "href": "/admin/finance/sales",
        "roles": ("MASTER_ADMIN",),
        "remark": None,
    },
    {
        "key": "finance_expenses",
        "label_zh": "支出管理",
        "href": "/admin/finance/expenses",
        "roles": ("MASTER_ADMIN",),
        "remark": None,
    },
    {
        "key": "finance_payroll",
        "label_zh": "薪酬 / 出勤報表",
        "href": "/admin/finance/payroll",
        "roles": ("MASTER_ADMIN",),
        "remark": None,
    },
    {
        "key": "whatsapp_settings",
        "label_zh": "Whatsapp 設定",
        "href": "/admin/settings/whatsapp",
        "roles": ("MASTER_ADMIN",),
        "remark": None,
    },
    {
        "key": "system_users",
        "label_zh": "系統帳號 · Access Rights",
        "href": "/admin/system-users",
        "roles": ("MASTER_ADMIN",),
        "remark": "masterzoe / masterfung 專用",
    },
    {
        "key": "admin_dashboard",
        "label_zh": "後台面板",
        "href": "/admin",
        "roles": ("MASTER_ADMIN", "CLERK"),
        "remark": None,
    },
    {
        "key": "payments",
        "label_zh": "付款紀錄",
        "href": "/admin/payments",
        "roles": ("MASTER_ADMIN", "CLERK"),
        "remark": None,
    },
    {
        "key": "coach_attendance",
        "label_zh": "教練出勤",
        "href": "/coach/attendance",
        "roles": ("MASTER_ADMIN",),
        "remark": None,
    },
]


def normalize_access_role(raw_role: str | None, username: str | None = None) -> AccessRole:
    """Map DB role + master username list to access role."""
    uname = (username or "").strip().lower()
    if uname in MASTER_ADMIN_USERNAMES:
        return "MASTER_ADMIN"
    r = (raw_role or "").strip().upper()
    if r == "MASTER_ADMIN":
        return "MASTER_ADMIN"
    if r == "COACH":
        return "COACH"
    return "CLERK"


def is_master_admin(username: str | None, role: str | None = None) -> bool:
    return normalize_access_role(role, username) == "MASTER_ADMIN"


def permissions_for_role(access_role: AccessRole) -> list[str]:
    return [f["key"] for f in ACCESS_FEATURES if access_role in f["roles"]]


def allowed_hrefs_for_role(access_role: AccessRole) -> list[str]:
    return [str(f["href"]) for f in ACCESS_FEATURES if access_role in f["roles"]]


def can_access_href(access_role: AccessRole, href: str) -> bool:
    if access_role == "MASTER_ADMIN":
        return True
    allowed = allowed_hrefs_for_role(access_role)
    return any(
        href == h or (h != "/admin" and href.startswith(f"{h}/"))
        for h in allowed
    )


def access_matrix_rows() -> list[dict]:
    """Excel-style matrix for admin UI."""
    roles: tuple[AccessRole, ...] = ("MASTER_ADMIN", "COACH", "CLERK")
    role_labels = {"MASTER_ADMIN": "Masteradmin", "COACH": "PT", "CLERK": "clerk"}
    out: list[dict] = []
    for feat in ACCESS_FEATURES:
        if feat["key"] == "system_users":
            continue
        out.append(
            {
                "key": feat["key"],
                "label_zh": feat["label_zh"],
                "href": feat["href"],
                "remark": feat.get("remark"),
                "matrix": {role_labels[r]: r in feat["roles"] for r in roles},
            }
        )
    return out
