import pytest

from backend.tests.test_flows import compose

pytestmark = pytest.mark.django_db


def test_settings_scope_and_secret_redaction(staff_client, admin_client, settings):
    compose(staff_client)
    compose(admin_client, sender="admin@onesmarter.com")
    settings.EMAIL_HOST_PASSWORD = "do-not-return-secret"
    settings.EMAIL_HOST_USER = "private-smtp-login"
    response = staff_client.get("/api/settings")
    assert response.status_code == 200
    data = response.json()
    assert data["delivery_counts"]["queued"] == 1
    assert data["can_manage_senders"] is False
    assert data["sender_addresses"] == ["staff@onesmarter.com"]
    assert b"do-not-return-secret" not in response.content
    assert b"private-smtp-login" not in response.content
    assert admin_client.get("/api/settings").json()["can_manage_senders"] is True
