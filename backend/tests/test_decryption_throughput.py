import json
from unittest.mock import Mock

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext

from backend.apps.core import conversations, crypto, keyring
from backend.apps.core.models import Attachment, Conversation, Message, MetadataToken
from backend.keyservice import protocol
from backend.tests.test_flows import compose

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize("message_count", [10, 100])
def test_historical_headers_have_constant_query_cost(staff_client, monkeypatch, message_count):
    conversation = Conversation.objects.get(pk=compose(staff_client).json()["id"])
    Message.objects.bulk_create(
        [
            Message(
                conversation=conversation, staff=conversation.owner, body_ciphertext="synthetic"
            )
            for _ in range(message_count - 1)
        ]
    )
    # Isolate ORM/serialization cost; real decryption and authorization are
    # covered by the batch and recipient-visibility regressions.
    monkeypatch.setattr(crypto, "decrypt_many", lambda values: [b"synthetic"] * len(values))
    with CaptureQueriesContext(connection) as queries:
        result = conversations.detail(conversation)
    assert len(result["messages"]) == message_count
    assert len(queries) <= 5
    assert all(m["headers"]["from_email"] == conversation.sender for m in result["messages"])


def test_thread_batches_only_visible_content(staff_client, monkeypatch):
    response = compose(staff_client)
    conversation = Conversation.objects.get(pk=response.json()["id"])
    for i in range(39):
        message = Message(conversation=conversation, staff=conversation.owner)
        message.body_ciphertext = crypto.encrypt(
            str(i).encode(), conversations.message_context(message)
        )
        message.save()
    message = conversation.messages.first()
    for i in range(20):
        item = Attachment(
            organization=conversation.organization, message=message, size=1, state="available"
        )
        item.name_ciphertext = crypto.encrypt(
            f"file{i}.txt".encode(), crypto.context(item.organization_id, "filename", item.pk)
        )
        item.save()
    bulk = Mock(wraps=crypto.decrypt_many)
    monkeypatch.setattr(crypto, "decrypt_many", bulk)
    result = conversations.detail(conversation)
    assert len(result["messages"]) == 40
    bulk.assert_called_once()
    assert len(bulk.call_args.args[0]) == 61


def test_duplicate_envelopes_are_unwrapped_once_but_never_cached_between_calls(
    org, settings, monkeypatch
):
    context = crypto.context(org.pk, "subject", "test")
    value = crypto.encrypt(b"synthetic", context)
    dek = crypto.unwrap(json.loads(value), context)
    remote = Mock()
    remote.call.return_value = {"deks": [protocol.encode(dek)]}
    monkeypatch.setattr(keyring, "service", lambda: remote)
    settings.KEY_PROTECTOR = "key-service"
    for _ in range(2):
        assert crypto.decrypt_many([(value, context)] * 61) == [b"synthetic"] * 61
    assert remote.call.call_count == 2
    assert len(remote.call.call_args.kwargs["items"]) == 1


def test_document_page_and_word_search_decrypt_only_page(staff_client, monkeypatch):
    conversation = Conversation.objects.get(pk=compose(staff_client).json()["id"])
    message = conversation.messages.first()
    for i in range(55):
        item = Attachment(
            organization=conversation.organization, message=message, size=1, state="available"
        )
        item.name_ciphertext = crypto.encrypt(
            f"report {i}.txt".encode(), crypto.context(item.organization_id, "filename", item.pk)
        )
        item.save()
    bulk = Mock(wraps=crypto.decrypt_many)
    monkeypatch.setattr(crypto, "decrypt_many", bulk)
    result = staff_client.get("/api/evidence?view=documents&page=2&q=report")
    assert result.status_code == 200
    assert result.json()["count"] == 55
    assert len(result.json()["results"]) == 25
    assert len(bulk.call_args.args[0]) == 26  # 25 filenames + one unique subject
    assert all(len(value) == 64 for value in MetadataToken.objects.values_list("token", flat=True))
    assert staff_client.get("/api/evidence?view=documents&sort=filename").status_code == 400


def test_search_fails_explicitly_until_old_records_are_indexed(staff_client):
    from django.core.management import call_command

    compose(staff_client)
    Conversation.objects.update(search_indexed=False)
    assert staff_client.get("/api/conversations?q=secure").status_code == 503
    call_command("rebuild_search_index")
    assert staff_client.get("/api/conversations?q=secure").status_code == 200
