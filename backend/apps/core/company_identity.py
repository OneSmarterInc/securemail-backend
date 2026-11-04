"""Company mailbox eligibility; account roles and permissions remain separate."""

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email


def is_company_address(value: str, domain: str | None = None) -> bool:
    if not isinstance(value, str) or value != value.strip():
        return False
    try:
        validate_email(value)
    except ValidationError:
        return False
    value = value.lower()
    company = domain or settings.COMPANY_DOMAIN
    return value.rsplit("@", 1)[-1] == company.lower() or (
        company.lower() == settings.COMPANY_DOMAIN.lower()
        and value in settings.COMPANY_EMAIL_ALLOWLIST
    )
