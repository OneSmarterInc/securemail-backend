"""Invitation-bound presentation. Never selects recipients or authorizes access."""

import base64
import binascii
import json
import re
import struct
import zlib

from . import crypto
from .models import ApiMessage


def luminance(color):
    channels = [int(color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    channels = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return sum(c * weight for c, weight in zip(channels, (0.2126, 0.7152, 0.0722)))


def validate_theme(theme):
    if not isinstance(theme, dict) or set(theme) - {"name", "primary", "background", "logo_png"}:
        raise ValueError("Theme supports name, primary, background and logo_png only.")
    name = theme.get("name", "")
    if (
        not isinstance(name, str)
        or not 1 <= len(name.strip()) <= 80
        or any(ord(c) < 32 for c in name)
    ):
        raise ValueError("Theme name must contain 1–80 printable characters.")
    result = {"name": name.strip(), "primary": "#117c78", "background": "#f5f7fa"}
    for field in ("primary", "background"):
        value = theme.get(field, result[field])
        if not isinstance(value, str) or not re.fullmatch(r"#[0-9a-fA-F]{6}", value):
            raise ValueError("Theme colors must be six-digit hex values.")
        result[field] = value
    if 1.05 / (luminance(result["primary"]) + 0.05) < 4.5:
        raise ValueError("Primary color must contrast with white text at least 4.5:1.")
    if (luminance(result["background"]) + 0.05) / (luminance("#172b3c") + 0.05) < 4.5:
        raise ValueError("Background must contrast with dark portal text at least 4.5:1.")
    if "logo_png" in theme:
        value = theme["logo_png"]
        if not isinstance(value, str) or len(value) > 90000:
            raise ValueError("Logo must be a base64 PNG of at most 64 KiB.")
        try:
            raw = base64.b64decode(value, validate=True)
            if len(raw) > 65536 or raw[:8] != b"\x89PNG\r\n\x1a\n":
                raise ValueError
            position, first, ended = 8, True, False
            while position < len(raw):
                length = struct.unpack(">I", raw[position : position + 4])[0]
                kind = raw[position + 4 : position + 8]
                chunk = raw[position + 8 : position + 8 + length]
                crc = struct.unpack(">I", raw[position + 8 + length : position + 12 + length])[0]
                if zlib.crc32(kind + chunk) != crc:
                    raise ValueError
                if first:
                    if kind != b"IHDR" or length != 13:
                        raise ValueError
                    width, height = struct.unpack(">II", chunk[:8])
                    if not (1 <= width <= 512 and 1 <= height <= 512):
                        raise ValueError
                    first = False
                position += length + 12
                if kind == b"IEND":
                    ended = length == 0 and position == len(raw)
                    break
            if not ended:
                raise ValueError
        except (ValueError, binascii.Error, struct.error):
            raise ValueError(
                "Logo must be a valid PNG, at most 512 × 512 pixels and 64 KiB."
            ) from None
        result["logo_png"] = value
    return result


def presentation(conversation):
    binding = ApiMessage.objects.filter(conversation=conversation).first()
    if not binding or not binding.presentation_ciphertext:
        return {}
    return json.loads(
        crypto.decrypt(
            binding.presentation_ciphertext,
            crypto.context(conversation.organization_id, "api-presentation", conversation.pk),
        )
    )


def recipient_theme(conversation):
    return presentation(conversation).get("theme")


def replies_allowed(conversation):
    try:
        return conversation.apimessage.allow_reply
    except ApiMessage.DoesNotExist:
        return True


def require_recipient_reply(conversation):
    from .http import Problem

    if not replies_allowed(conversation):
        raise Problem(
            "This conversation is read-only. Replies and uploads are disabled.",
            "replies_disabled",
            403,
        )
