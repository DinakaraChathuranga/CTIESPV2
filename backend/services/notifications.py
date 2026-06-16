"""
Admin notification helper.

Sends operational alerts (OpenAI quota, RSS failures, pipeline errors,
email send failures) to opted-in recipients via Microsoft Graph API.

Includes throttling: same category emails are rate-limited to 1 per 30 min
to avoid alert spam during persistent failures.
"""
from __future__ import annotations
import json
import logging
import time
import urllib.request
import urllib.error
from typing import Literal

import msal
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from models.db_models import NotificationRecipient

logger = logging.getLogger(__name__)

Category = Literal["openai", "feeds", "pipeline", "email_send"]

# Throttling: category -> last_sent_unix_ts
_last_sent: dict[str, float] = {}
THROTTLE_SECONDS = 30 * 60  # 30 minutes


CATEGORY_FIELD_MAP = {
    "openai":     "notify_openai",
    "feeds":      "notify_feeds",
    "pipeline":   "notify_pipeline",
    "email_send": "notify_email_send",
}

CATEGORY_LABEL = {
    "openai":     "OpenAI API",
    "feeds":      "Feed Polling",
    "pipeline":   "Auto-Pipeline",
    "email_send": "Email Delivery",
}


async def get_recipients(db: AsyncSession, category: Category) -> list[NotificationRecipient]:
    field_name = CATEGORY_FIELD_MAP[category]
    field = getattr(NotificationRecipient, field_name)
    q = await db.execute(
        select(NotificationRecipient).where(
            NotificationRecipient.enabled.is_(True),
            field.is_(True),
        )
    )
    return list(q.scalars().all())


def _build_html(subject: str, message: str, category: Category) -> str:
    label = CATEGORY_LABEL.get(category, category)
    return f"""\
<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f4f6f8;font-family:Arial,sans-serif;">
<table width="100%" cellspacing="0" cellpadding="0" style="background:#f4f6f8;padding:24px 0;">
<tr><td align="center">
  <table width="640" cellspacing="0" cellpadding="0" style="background:#fff;border:1px solid #d9dee5;border-top:6px solid #d71920;">
    <tr><td style="padding:24px 30px;">
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;font-weight:bold;">
        CTI Platform — System Alert
      </div>
      <h1 style="margin:8px 0 0;font-size:22px;color:#111827;">{subject}</h1>
      <div style="display:inline-block;margin-top:8px;padding:4px 10px;background:#fef3c7;color:#92400e;font-size:12px;border-radius:4px;font-weight:bold;">
        {label}
      </div>
    </td></tr>
    <tr><td style="padding:0 30px 24px;font-size:14px;line-height:22px;color:#374151;">
      <p style="margin:0;white-space:pre-wrap;">{message}</p>
    </td></tr>
    <tr><td style="padding:14px 30px;background:#111827;color:#e5e7eb;font-size:12px;">
      This is an automated alert from the CTI Automation Platform.<br>
      Manage your notification preferences from the Notifications page.
    </td></tr>
  </table>
</td></tr></table>
</body></html>"""


async def send_admin_alert(db: AsyncSession, category: Category, subject: str, message: str) -> bool:
    """
    Send an operational alert to opted-in recipients.
    Returns True if sent, False if throttled or no recipients or send failed.
    """
    # Throttle check
    last = _last_sent.get(category, 0)
    if time.time() - last < THROTTLE_SECONDS:
        logger.info(f"[Notify] Throttled {category} alert (sent {int(time.time()-last)}s ago)")
        return False

    recipients = await get_recipients(db, category)
    if not recipients:
        logger.info(f"[Notify] No recipients opted in for {category}")
        return False

    # Acquire OAuth2 token (same Graph API path as report emails)
    if not (settings.SMTP_USER and settings.SMTP_CLIENT_ID and settings.SMTP_CLIENT_SECRET):
        logger.warning(f"[Notify] Graph API not configured, cannot send {category} alert")
        return False

    try:
        app = msal.ConfidentialClientApplication(
            settings.SMTP_CLIENT_ID,
            authority=f"https://login.microsoftonline.com/{settings.SMTP_TENANT_ID}",
            client_credential=settings.SMTP_CLIENT_SECRET,
        )
        token_result = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        token = token_result.get("access_token")
        if not token:
            logger.error(f"[Notify] OAuth2 token error: {token_result.get('error_description')}")
            return False

        to_list = [{"emailAddress": {"address": r.email}} for r in recipients]
        payload = {
            "message": {
                "subject": f"[CTI Platform Alert] {subject}",
                "body": {"contentType": "HTML", "content": _build_html(subject, message, category)},
                "toRecipients": to_list,
            }
        }

        url = f"https://graph.microsoft.com/v1.0/users/{settings.SMTP_USER}/sendMail"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=15)
        _last_sent[category] = time.time()
        logger.info(f"[Notify] Sent {category} alert to {len(recipients)} recipient(s): {subject}")
        return True

    except urllib.error.HTTPError as e:
        logger.error(f"[Notify] Graph API HTTP {e.code}: {e.read().decode()[:200]}")
        return False
    except Exception as e:
        logger.error(f"[Notify] Send failed: {e}")
        return False


def send_admin_alert_sync(db_url_unused, category: Category, subject: str, message: str) -> bool:
    """Sync wrapper for use inside Celery tasks. Creates its own DB session."""
    import asyncio
    from core.database import AsyncSessionLocal

    async def _run():
        async with AsyncSessionLocal() as db:
            return await send_admin_alert(db, category, subject, message)

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(_run())
    except Exception as e:
        logger.error(f"[Notify] Sync send wrapper failed: {e}")
        return False
