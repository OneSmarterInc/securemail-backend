"""Escaped, self-contained notification HTML with a plain-text alternative."""

import re
from pathlib import Path
from urllib.parse import urlsplit

from django.template import Context, Engine

_engine = Engine(dirs=[str(Path(__file__).parent / "templates")], autoescape=True)


def notification_html(data: dict, *, protected: bool) -> str:
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
    return _engine.get_template("notification.html").render(
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
