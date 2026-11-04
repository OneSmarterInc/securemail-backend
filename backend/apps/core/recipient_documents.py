"""Paginated documents scoped to the currently verified recipient grant."""

from django.db.models import Q
from rest_framework.response import Response

from . import crypto, search_index
from .conversations import recipient, visible_messages
from .http import Problem, endpoint
from .models import Attachment
from .services import audit, paginate, rate_limit


@endpoint(["GET"])
def documents(request):
    grant = recipient(request)
    rate_limit(request, "recipient_documents", str(grant.pk), maximum=60, seconds=60)
    visible = visible_messages(grant.conversation.messages.all(), grant)
    query = Attachment.objects.filter(message__in=visible, state="available")
    search = request.query_params.get("q", "").strip()
    if len(search) > 200:
        raise Problem("Search is limited to 200 characters.")
    if search and query.filter(search_indexed=False).exists():
        raise Problem("Document search index needs rebuilding.", "search_index_unavailable", 503)
    for word in search_index.words(search):
        query = query.filter(
            Q(pk__in=search_index.ids(grant.conversation.organization_id, "filename", word))
            | Q(message__staff__email__icontains=word)
            | Q(message__grant__email__icontains=word)
            | Q(created_at__icontains=word)
        )
    items, meta = paginate(
        query.select_related("message__staff", "message__grant", "message__conversation"),
        request,
        ordering={"date": "created_at", "sender": "message__mail_headers__from_email"},
        default="-date",
    )
    items = list(items)
    names = crypto.decrypt_many(
        [(a.name_ciphertext, crypto.context(a.organization_id, "filename", a.pk)) for a in items]
    )
    rows = []
    for item, name in zip(items, names, strict=True):
        message = item.message
        rows.append(
            {
                "id": str(item.pk),
                "name": name.decode(),
                "state": item.state,
                "sender": message.mail_headers.get("from_email")
                or (message.conversation.sender if message.staff_id else message.grant.email),
                "date": message.created_at,
            }
        )
    audit(
        grant.conversation.organization_id,
        grant.pk,
        "recipient.documents_viewed",
        "conversation",
        grant.conversation_id,
    )
    return Response({"results": rows, **meta})
