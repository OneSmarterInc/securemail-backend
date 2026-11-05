"""Escaped, self-contained notification HTML with a plain-text alternative."""

import re
from pathlib import Path
from urllib.parse import urlsplit

from django.template import Context, Engine

_engine = Engine(dirs=[str(Path(__file__).parent / "templates")], autoescape=True)


def notification_content(data: dict, *, source: str | None = None) -> dict:
    """Apply service branding after the worker resolves the authorized source."""
    result = dict(data)
    if source == "selfpay":
        if result.get("portal_challenge_id"):
            result["subject"] = "Your MySelfPay verification code"
        result["body"] = result["body"].replace(
            "Kind regards,\nOneSmarter Support\nSupporting MySelfPay communications",
            "Kind regards,\nPatient Care\nMySelfPay",
        )
    return result


def notification_html(data: dict, *, protected: bool, source: str | None = None) -> str:
    data = notification_content(data, source=source)
    link = data.get("link", "")
    if link:
        parsed = urlsplit(link)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError("Invalid notification link")
    code = ""
    if data.get("challenge_id") or data.get("portal_challenge_id"):
        match = re.search(r"one-time code is (\d{6})\.", data["body"])
        code = match.group(1) if match else ""
    action = "Open secure portal" if protected else "Continue to OneSmarter"
    if data.get("invitation_id"):
        action = "Set up your account"
    elif data.get("notification_kind") == "selfpay_clinic_request":
        action = "Review appointment request"
    template = "selfpay_notification.html" if source == "selfpay" else "notification.html"
    if source == "selfpay" and action == "Continue to OneSmarter":
        action = "View in Secure Mail"
    return _engine.get_template(template).render(
        Context(
            {
                "title": data["subject"],
                "body": data["body"],
                "link": link,
                "code": code,
                "action": action,
                "protected": protected,
            },
            autoescape=True,
        )
    )
