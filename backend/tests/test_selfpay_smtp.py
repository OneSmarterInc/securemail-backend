from unittest.mock import Mock

import pytest

from backend.apps.core import smtp_settings
from backend.apps.core.senders import SenderUnavailable


@pytest.fixture
def dedicated(settings):
    settings.SELFPAY_SMTP_ENABLED = True
    settings.SELFPAY_EMAIL_HOST = "smtp.ionos.com"
    settings.SELFPAY_EMAIL_HOST_USER = "patientcare@example.test"
    settings.SELFPAY_EMAIL_HOST_PASSWORD = "synthetic-only-password"
    settings.SELFPAY_FROM_EMAIL = "patientcare@example.test"
    settings.SELFPAY_EMAIL_PORT = 587
    settings.SELFPAY_EMAIL_USE_TLS = True
    settings.SELFPAY_EMAIL_USE_SSL = False
    settings.EMAIL_HOST = "ordinary.example.test"
    settings.EMAIL_HOST_USER = "ordinary@example.test"
    settings.EMAIL_HOST_PASSWORD = "synthetic-ordinary-password"
    settings.EMAIL_PORT = 587
    settings.EMAIL_USE_TLS = True
    settings.EMAIL_USE_SSL = False


@pytest.mark.parametrize("source", [None, "another-integration"])
def test_other_notifications_keep_general_transport(dedicated, monkeypatch, source):
    factory = Mock()
    monkeypatch.setattr(smtp_settings, "SMTPBackend", factory)
    sender, _ = smtp_settings.notification_connection(source=source)
    assert sender == "support@onesmarter.com"
    assert factory.call_args.kwargs["host"] == "ordinary.example.test"


@pytest.mark.parametrize(
    "name,value",
    [
        ("SELFPAY_EMAIL_HOST_PASSWORD", ""),
        ("SELFPAY_EMAIL_HOST_USER", ""),
        ("SELFPAY_EMAIL_USE_TLS", False),
        ("SELFPAY_EMAIL_USE_SSL", True),
        ("SELFPAY_EMAIL_PORT", 25),
        ("SELFPAY_FROM_EMAIL", "invalid\r\nBcc: attacker@example.test"),
    ],
)
def test_invalid_selfpay_configuration_never_falls_back(
    dedicated, settings, monkeypatch, name, value
):
    setattr(settings, name, value)
    factory = Mock()
    monkeypatch.setattr(smtp_settings, "SMTPBackend", factory)
    with pytest.raises(SenderUnavailable):
        smtp_settings.notification_connection(source="selfpay")
    factory.assert_not_called()
