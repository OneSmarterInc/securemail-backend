"""Exact-origin credentialed CORS for the separately hosted browser client.

This never replaces CSRF or endpoint authorization. No wildcard origins, headers,
or methods are reflected. The key-service maintenance surface is excluded.
"""

from django.conf import settings
from django.http import HttpResponse
from django.middleware.csrf import get_token
from django.utils.cache import patch_vary_headers

METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
HEADERS = frozenset({"content-type", "x-csrftoken", "idempotency-key"})


class ApiCorsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.path.startswith(("/api/", "/recipient-api/")):
            return self.get_response(request)
        origin = request.headers.get("Origin", "")
        allowed = origin in settings.CORS_ALLOWED_ORIGINS
        preflight = (
            request.method == "OPTIONS" and "Access-Control-Request-Method" in request.headers
        )
        if preflight:
            method = request.headers["Access-Control-Request-Method"]
            headers = {
                part.strip().lower()
                for part in request.headers.get("Access-Control-Request-Headers", "").split(",")
                if part.strip()
            }
            valid = allowed and method in METHODS and headers <= HEADERS
            response = HttpResponse(status=204 if valid else 403)
            if valid:
                response["Access-Control-Allow-Methods"] = ", ".join(sorted(METHODS))
                response["Access-Control-Allow-Headers"] = ", ".join(sorted(HEADERS))
                response["Access-Control-Max-Age"] = "600"
        else:
            if allowed:
                get_token(request)  # Let inner CsrfViewMiddleware set the host-only cookie.
            response = self.get_response(request)
            if allowed:
                response["X-CSRFToken"] = get_token(request)
                response["Access-Control-Expose-Headers"] = "X-CSRFToken, X-Request-ID"
        if allowed:
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Credentials"] = "true"
        patch_vary_headers(response, ("Origin",))
        response["Cache-Control"] = "no-store"
        return response
