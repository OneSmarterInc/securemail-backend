from datetime import timedelta
from unittest.mock import Mock

import pytest
from django.test import RequestFactory
from django.utils import timezone

from backend.apps.core.client_ip import client_ip
from backend.apps.core.http import Problem
from backend.apps.core.models import RateBucket
from backend.apps.core.services import keyed, rate_limit


@pytest.mark.django_db
def test_correct_password_cannot_bypass_source_network_throttle(client, staff, monkeypatch):
    from backend.apps.core import auth

    now = timezone.now()
    monkeypatch.setattr("backend.apps.core.services.timezone.now", lambda: now)
    authenticate = Mock(wraps=auth.authenticate)
    monkeypatch.setattr(auth, "authenticate", authenticate)

    def login(password, peer, email=None):
        return client.post(
            "/api/auth/login",
            {"email": email or staff.email, "password": password},
            content_type="application/json",
            REMOTE_ADDR=peer,
        )

    for index in range(10):
        assert login("wrong-password", f"198.51.100.{index + 1}").status_code == 401
    correct = "A-strong-test-only-password!"
    for password in (correct, "wrong-password"):
        response = login(password, "198.51.100.100", staff.email.upper())
        assert response.status_code == 429
        assert response["Retry-After"] == "6"
        assert response.json()["error"]["code"] == "rate_limited"
        assert "pending_user" not in client.session
    assert authenticate.call_count == 10
    now += timedelta(seconds=5)
    response = login(correct, "198.51.100.101")
    assert response.status_code == 429
    assert response["Retry-After"] == "1"
    assert authenticate.call_count == 10
    now += timedelta(seconds=1)
    assert login(correct, "198.51.100.102").status_code == 200
    assert authenticate.call_count == 11
    assert client.session["pending_user"] == staff.pk
    # A successful password does not reset the account budget.
    assert login(correct, "198.51.100.103").status_code == 429


def request(peer="127.0.0.1", forwarded="198.51.100.1"):
    return RequestFactory().get("/", REMOTE_ADDR=peer, HTTP_X_REAL_IP=forwarded)


@pytest.mark.parametrize("peer", ["203.0.113.1", "127.0.0.1"])
def test_untrusted_forwarding_is_ignored(settings, peer):
    settings.TRUSTED_PROXY_IPS = set()
    assert client_ip(request(peer)) == peer


def test_trusted_proxy_and_unix_boundary(settings):
    settings.TRUSTED_PROXY_IPS = {"127.0.0.1"}
    assert client_ip(request()) == "198.51.100.1"
    settings.TRUSTED_PROXY_UNIX_SOCKET = True
    assert client_ip(request("")) == "198.51.100.1"
    # Socket opt-in does not authorize any TCP peer.
    assert client_ip(request("203.0.113.1")) == "203.0.113.1"
    assert client_ip(request(forwarded="::ffff:198.51.100.1")) == "198.51.100.1"


@pytest.mark.parametrize("value", ["", "unknown", "1.2.3.4, 5.6.7.8", "1.2.3.4:80", "fe80::1%eth0"])
def test_malformed_trusted_header_rejected(settings, value):
    settings.TRUSTED_PROXY_IPS = {"127.0.0.1"}
    with pytest.raises(Problem) as error:
        client_ip(request(forwarded=value))
    assert error.value.status_code == 400


@pytest.mark.django_db
def test_bucket_refill_cap_and_clock_rollback(monkeypatch):
    now = timezone.now()
    monkeypatch.setattr("backend.apps.core.services.timezone.now", lambda: now)
    req = request()
    for _ in range(10):
        rate_limit(req, "login", "a@example.test")
    for advance in [0, 29]:
        now += timedelta(seconds=advance)
        with pytest.raises(Problem) as error:
            rate_limit(req, "login", "a@example.test")
        assert error.value.status_code == 429
    now += timedelta(seconds=1)
    rate_limit(req, "login", "a@example.test")
    now -= timedelta(seconds=60)
    with pytest.raises(Problem):
        rate_limit(req, "login", "a@example.test")
    now += timedelta(days=1)
    for _ in range(10):
        rate_limit(req, "login", "a@example.test")
    with pytest.raises(Problem):
        rate_limit(req, "login", "a@example.test")
    assert RateBucket.objects.count() == 3


@pytest.mark.django_db
def test_identity_and_proxy_ip_isolation(settings):
    settings.TRUSTED_PROXY_IPS = {"127.0.0.1"}
    a, b = request(), request(forwarded="198.51.100.2")
    rate_limit(a, "login", "alice@example.test", maximum=1)
    rate_limit(a, "login", "bob@example.test", maximum=1)
    # Changing source does not bypass the account-wide limit.
    with pytest.raises(Problem):
        rate_limit(b, "login", "ALICE@example.test", maximum=1)
    rate_limit(a, "landing", maximum=1)
    with pytest.raises(Problem):
        rate_limit(a, "landing", maximum=1)
    rate_limit(b, "landing", maximum=1)


@pytest.mark.django_db
def test_login_api_other_account_survives(settings, client, monkeypatch):
    settings.TRUSTED_PROXY_IPS = {"127.0.0.1"}
    monkeypatch.setattr("backend.apps.core.auth.authenticate", lambda *a, **kw: None)

    def login(email):
        return client.post(
            "/api/auth/login",
            {"email": email, "password": "invalid-test-only"},
            content_type="application/json",
            HTTP_X_REAL_IP="198.51.100.1",
        )

    for _ in range(10):
        assert login("a@onesmarter.com").status_code == 401
    assert login("a@onesmarter.com").status_code == 429
    assert login("b@onesmarter.com").status_code == 401


@pytest.mark.django_db
def test_password_spray_stops_before_identity_allocation(monkeypatch):
    now = timezone.now()
    monkeypatch.setattr("backend.apps.core.services.timezone.now", lambda: now)
    for index in range(50):
        rate_limit(request(), "login", f"user{index}@example.test")
    count = RateBucket.objects.count()
    for index in range(50, 200):
        with pytest.raises(Problem):
            rate_limit(request(), "login", f"user{index}@example.test")
    assert RateBucket.objects.count() == count


@pytest.mark.django_db
def test_login_account_minute_budget_and_no_global_lockout(client, monkeypatch):
    now = timezone.now()
    monkeypatch.setattr("backend.apps.core.services.timezone.now", lambda: now)
    calls = []
    monkeypatch.setattr(
        "backend.apps.core.auth.authenticate",
        lambda *args, **kwargs: calls.append(kwargs["username"]),
    )
    # Even an exhausted bucket left by the previous deployment cannot block login.
    RateBucket.objects.create(key=keyed("token-rate:v1:login:global"), credits=0, refilled_at=now)

    def login(email, peer):
        return client.post(
            "/api/auth/login",
            {"email": email, "password": "invalid-test-only"},
            content_type="application/json",
            REMOTE_ADDR=peer,
        )

    for index in range(10):
        assert login("a@onesmarter.com", f"198.51.100.{index + 1}").status_code == 401
    assert login("A@onesmarter.com", "198.51.100.100").status_code == 429
    assert len(calls) == 10  # Throttled requests do not run password hashing.
    assert login("b@onesmarter.com", "203.0.113.1").status_code == 401
    now += timedelta(minutes=1)
    for _ in range(10):
        assert login("a@onesmarter.com", "203.0.113.2").status_code == 401
    assert login("a@onesmarter.com", "203.0.113.3").status_code == 429
