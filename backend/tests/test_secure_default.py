import pytest

from backend.apps.core.mail import payload, process_job
from backend.apps.core.models import Conversation, DeliveryJob
from backend.tests.test_flows import compose

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(
    "recipient", ["colleague@onesmarter.com", "sara@example.com", "info@kormic.ai"]
)
def test_all_recipients_default_to_portal(staff_client, settings, recipient):
    settings.COMPANY_EMAIL_ALLOWLIST = frozenset({"info@kormic.ai"})
    result = compose(
        staff_client, mode="ordinary", to=[recipient], subject="Nophi notes", body="Private content"
    )
    assert result.status_code == 201
    conversation = Conversation.objects.get(pk=result.json()["id"])
    assert conversation.protected
    assert conversation.routing_reason == "secure_default"
    data = payload(DeliveryJob.objects.get(conversation=conversation))
    assert data["link"]
    assert "Private content" not in data["body"]


@pytest.mark.parametrize("recipient", ["colleague@onesmarter.com", "sara@example.com"])
def test_explicit_nophi_required_for_normal_delivery(staff_client, staff, recipient):
    staff.can_nophi = True
    staff.save()
    args = dict(mode="ordinary", to=[recipient], body="Routine update", nophi_override=True)
    assert compose(staff_client, **args).status_code == 400
    result = compose(staff_client, **args, nophi_acknowledged=True)
    assert result.status_code == 201
    conversation = Conversation.objects.get(pk=result.json()["id"])
    assert not conversation.protected
    job = DeliveryJob.objects.get(conversation=conversation)
    assert payload(job)["body"] == "Routine update"
    process_job(job.pk)
    job.refresh_from_db()
    assert job.state == "development_delivered"


def test_worker_cancels_retired_internal_delivery(staff_client):
    result = compose(staff_client, mode="ordinary", to=["colleague@onesmarter.com"], body="Private")
    conversation = Conversation.objects.get(pk=result.json()["id"])
    conversation.protected = False
    conversation.routing_reason = "internal_only"
    conversation.save()
    job = DeliveryJob.objects.get(conversation=conversation)
    process_job(job.pk)
    job.refresh_from_db()
    assert job.state == "cancelled"
    assert job.error_code == "route_policy_changed"
    assert job.attempts == 0
