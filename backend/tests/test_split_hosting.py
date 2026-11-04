import pytest
from django.test import Client


@pytest.fixture
def split(settings):
    settings.CORS_ALLOWED_ORIGINS = {"https://app.example.com"}
    settings.CSRF_TRUSTED_ORIGINS = ["https://app.example.com"]
    return Client(enforce_csrf_checks=True)


@pytest.mark.django_db
def test_cross_origin_csrf_still_required(split):
    origin = {"HTTP_ORIGIN": "https://app.example.com"}
    response = split.get("/api/auth/session", **origin)
    assert response["Access-Control-Allow-Origin"] == origin["HTTP_ORIGIN"]
    assert response["Access-Control-Allow-Credentials"] == "true"
    token = response["X-CSRFToken"]
    assert "csrftoken" in response.cookies
    assert not response.cookies["csrftoken"]["domain"]
    assert split.post("/api/auth/login", {}, **origin).status_code == 403
    # Valid CSRF reaches serializer validation (missing credentials), not a CSRF bypass.
    assert split.post("/api/auth/login", {}, HTTP_X_CSRFTOKEN=token, **origin).status_code == 400
    assert (
        split.post(
            "/api/auth/login", {}, HTTP_X_CSRFTOKEN=token, HTTP_ORIGIN="https://attacker.example"
        ).status_code
        == 403
    )


@pytest.mark.parametrize(
    "origin,headers,method,status",
    [
        ("https://app.example.com", "content-type,x-csrftoken,idempotency-key", "POST", 204),
        ("https://attacker.example", "content-type", "POST", 403),
        ("null", "content-type", "POST", 403),
        ("https://app.example.com", "x-forwarded-for", "POST", 403),
        ("https://app.example.com", "content-type", "TRACE", 403),
    ],
)
def test_preflight_exact_allowlist(split, origin, headers, method, status):
    response = split.options(
        "/recipient-api/recipient/verify",
        HTTP_ORIGIN=origin,
        HTTP_ACCESS_CONTROL_REQUEST_METHOD=method,
        HTTP_ACCESS_CONTROL_REQUEST_HEADERS=headers,
    )
    assert response.status_code == status
    assert "Origin" in response["Vary"]
    if origin != "https://app.example.com":
        assert "Access-Control-Allow-Origin" not in response


@pytest.mark.django_db
def test_untrusted_origin_cannot_read_csrf(split):
    response = split.get(
        "/api/auth/session", HTTP_ORIGIN="https://app.example.com.attacker.example"
    )
    assert "Access-Control-Allow-Origin" not in response
    assert "X-CSRFToken" not in response
