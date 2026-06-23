"""[F005][S003]
Feature: Balance Sync & Integrations
Step: WhatsApp Business API (Meta Cloud API) client
Logic: Send approved template messages for proactive reminders; dry-run when disabled or credentials missing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from .config import settings
from .logutil import log_event

GRAPH_API_VERSION = "v21.0"


@dataclass(frozen=True)
class WhatsAppSendResult:
    ok: bool
    dry_run: bool
    message_id: str | None = None
    error: str | None = None
    to: str | None = None
    template_name: str | None = None


def normalize_whatsapp_phone(phone: str) -> str:
    """[F005][S003] Meta Cloud API expects E.164 digits without '+'; default HK country code."""
    digits = "".join(ch for ch in phone if ch.isdigit())
    if not digits:
        return ""
    if digits.startswith("852"):
        return digits
    return f"852{digits.lstrip('0')}"


def _graph_messages_url(phone_number_id: str) -> str:
    base = settings.whatsapp_graph_api_base.rstrip("/")
    return f"{base}/{GRAPH_API_VERSION}/{phone_number_id.strip()}/messages"


class WhatsAppBusinessClient:
    """[F005][S003] Thin wrapper around Meta WhatsApp Cloud API template sends."""

    @property
    def enabled(self) -> bool:
        return settings.whatsapp_enabled

    @property
    def configured(self) -> bool:
        return bool(settings.whatsapp_phone_number_id.strip() and settings.whatsapp_access_token.strip())

    def status(self) -> dict[str, Any]:
        """[F005][S003] Safe status snapshot for admin UI (no secrets)."""
        keys: list[str] = []
        raw = settings.whatsapp_template_map.strip()
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    keys = sorted(str(k) for k in parsed.keys())
            except json.JSONDecodeError:
                keys = []
        return {
            "enabled": self.enabled,
            "configured": self.configured,
            "phone_number_id_set": bool(settings.whatsapp_phone_number_id.strip()),
            "access_token_set": bool(settings.whatsapp_access_token.strip()),
            "business_account_id_set": bool(settings.whatsapp_business_account_id.strip()),
            "app_id_set": bool(settings.whatsapp_app_id.strip()),
            "default_language": settings.whatsapp_default_language,
            "template_map_keys": keys,
        }

    def send_template(
        self,
        to_phone: str,
        template_name: str,
        *,
        language_code: str | None = None,
        body_parameters: list[str] | None = None,
    ) -> WhatsAppSendResult:
        """[F005][S003] Send a Meta-approved template message (required for proactive reminders)."""
        to = normalize_whatsapp_phone(to_phone)
        lang = (language_code or settings.whatsapp_default_language).strip() or "zh_HK"
        if not to:
            return WhatsAppSendResult(
                ok=False,
                dry_run=False,
                error="Invalid recipient phone.",
                to=to_phone,
                template_name=template_name,
            )

        if not self.enabled:
            log_event(
                "[F005][S003] whatsapp_dry_run_disabled",
                to_suffix=to[-4:],
                template=template_name,
            )
            return WhatsAppSendResult(ok=True, dry_run=True, to=to, template_name=template_name)

        if not self.configured:
            log_event(
                "[F005][S003] whatsapp_dry_run_missing_credentials",
                to_suffix=to[-4:],
                template=template_name,
            )
            return WhatsAppSendResult(
                ok=True,
                dry_run=True,
                to=to,
                template_name=template_name,
                error="Missing WHATSAPP_PHONE_NUMBER_ID or WHATSAPP_ACCESS_TOKEN — message logged only.",
            )

        payload: dict[str, Any] = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "template",
            "template": {
                "name": template_name,
                "language": {"code": lang},
            },
        }
        if body_parameters:
            payload["template"]["components"] = [
                {
                    "type": "body",
                    "parameters": [{"type": "text", "text": str(p)[:1024]} for p in body_parameters],
                }
            ]

        url = _graph_messages_url(settings.whatsapp_phone_number_id)
        headers = {
            "Authorization": f"Bearer {settings.whatsapp_access_token.strip()}",
            "Content-Type": "application/json",
        }

        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(url, json=payload, headers=headers)
            data = resp.json() if resp.content else {}
            if resp.status_code >= 400:
                err = data.get("error", {}) if isinstance(data, dict) else {}
                msg = err.get("message") if isinstance(err, dict) else None
                msg = msg or resp.text or f"HTTP {resp.status_code}"
                log_event(
                    "[F005][S003] whatsapp_send_error",
                    status=resp.status_code,
                    template=template_name,
                    error=msg,
                )
                return WhatsAppSendResult(
                    ok=False,
                    dry_run=False,
                    error=str(msg),
                    to=to,
                    template_name=template_name,
                )
            messages = data.get("messages") if isinstance(data, dict) else None
            message_id = None
            if isinstance(messages, list) and messages:
                message_id = messages[0].get("id")
            log_event(
                "[F005][S003] whatsapp_send_ok",
                to_suffix=to[-4:],
                template=template_name,
                message_id=message_id,
            )
            return WhatsAppSendResult(
                ok=True,
                dry_run=False,
                message_id=message_id,
                to=to,
                template_name=template_name,
            )
        except httpx.HTTPError as exc:
            log_event("[F005][S003] whatsapp_send_http_error", template=template_name, error=str(exc))
            return WhatsAppSendResult(
                ok=False,
                dry_run=False,
                error=str(exc),
                to=to,
                template_name=template_name,
            )


def get_whatsapp_client() -> WhatsAppBusinessClient:
    return WhatsAppBusinessClient()


def resolve_meta_template(internal_key: str) -> dict[str, Any] | None:
    """[F005][S003] Map internal template key → Meta template config via WHATSAPP_TEMPLATE_MAP JSON."""
    raw = settings.whatsapp_template_map.strip()
    if not raw:
        return None
    try:
        mapping = json.loads(raw)
    except json.JSONDecodeError:
        log_event("[F005][S003] whatsapp_template_map_invalid_json")
        return None
    if not isinstance(mapping, dict):
        return None
    entry = mapping.get(internal_key)
    if not isinstance(entry, dict):
        return None
    name = entry.get("name") or entry.get("meta_name")
    if not name:
        return None
    body_params = entry.get("body_params") or entry.get("params") or []
    if not isinstance(body_params, list):
        body_params = []
    return {
        "name": str(name),
        "language": str(entry.get("language") or settings.whatsapp_default_language),
        "body_params": [str(k) for k in body_params],
    }


def build_body_parameters(param_keys: list[str], context: dict[str, str]) -> list[str]:
    """[F005][S003] Ordered Meta template body variables from rendered context."""
    return [context.get(key, "—") for key in param_keys]


def dispatch_reminder(
    to_phone: str,
    message: str,
    *,
    template_key: str | None = None,
    template_context: dict[str, str] | None = None,
) -> WhatsAppSendResult:
    """[F005][S003] Send reminder via Meta template when mapped; otherwise log-only dry run."""
    client = get_whatsapp_client()
    if template_key:
        meta = resolve_meta_template(template_key)
        if meta and template_context is not None:
            params = build_body_parameters(meta["body_params"], template_context)
            return client.send_template(
                to_phone,
                meta["name"],
                language_code=meta["language"],
                body_parameters=params,
            )
    log_event(
        "[F005][S003] whatsapp_no_template_mapping",
        template_key=template_key,
        preview=message[:120],
    )
    return WhatsAppSendResult(
        ok=True,
        dry_run=True,
        to=normalize_whatsapp_phone(to_phone) or to_phone,
        error="No WHATSAPP_TEMPLATE_MAP entry — message logged only.",
    )
