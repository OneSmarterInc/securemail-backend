import json
import logging
import traceback
from functools import wraps

from django.core.exceptions import RequestDataTooBig
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import api_view
from rest_framework.exceptions import APIException, PermissionDenied
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler

from .crypto import CryptoUnavailable


class Problem(APIException):
    status_code = 400

    def __init__(self, message: str, code: str = "invalid_request", status: int = 400):
        super().__init__({"message": message, "code": code})
        self.status_code = status


def exception_handler(exc, context):
    if isinstance(exc, RequestDataTooBig):
        return Response(
            {"error": {"code": "upload_too_large", "message": "Upload size limit exceeded."}},
            status=413,
        )
    if isinstance(exc, CryptoUnavailable):
        return Response(
            {
                "error": {
                    "code": "key_unavailable",
                    "message": "Protected content is temporarily unavailable.",
                }
            },
            status=503,
        )
    if isinstance(exc, DjangoValidationError):
        return Response(
            {"error": {"code": "validation_error", "message": "; ".join(exc.messages)}}, status=400
        )
    response = drf_exception_handler(exc, context)
    if response is None:
        logging.getLogger("securemail").error(
            json.dumps(
                {
                    "event": "api.unhandled",
                    "error_type": type(exc).__name__,
                    "request_id": getattr(context.get("request"), "request_id", ""),
                    "locations": [
                        {
                            "file": f.filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
                            "line": f.lineno,
                        }
                        for f in traceback.extract_tb(exc.__traceback__)[-5:]
                    ],
                }
            )
        )
        return Response(
            {
                "error": {
                    "code": "service_unavailable",
                    "message": "The service could not complete this request. Please retry.",
                }
            },
            status=503,
        )
    if response is not None:
        detail = response.data
        response.data = {
            "error": detail
            if isinstance(detail, dict) and "message" in detail
            else {"message": detail, "code": "request_denied"}
        }
    return response


def endpoint(methods, *, staff=False, admin=False):
    def decorate(function):
        @api_view(methods)
        @wraps(function)
        def wrapped(request, *args, **kwargs):
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                SessionAuthentication().enforce_csrf(request)
            request.user = request._request.user
            if staff or admin:
                user = request.user
                if not user.is_authenticated or user.status != "active" or not user.mfa_confirmed:
                    raise Problem("Sign in with MFA to continue.", "authentication_required", 401)
                if request.session.get(
                    "staff_version"
                ) != user.session_version or not request.session.get("mfa_at"):
                    raise Problem(
                        "Your session ended. Please sign in again.", "session_expired", 401
                    )
                if admin and user.role != "admin":
                    from .services import audit

                    audit(
                        user.organization,
                        user,
                        "access.admin_denied",
                        "account",
                        user.pk,
                        outcome="denied",
                    )
                    raise PermissionDenied("Administrator access is required.")
            return function(request, *args, **kwargs)

        return wrapped

    return decorate


def unavailable():
    raise Http404("This resource is unavailable.")
