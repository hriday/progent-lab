"""The password gate: redirect or 401 until signed in, bcrypt check, signed cookie, lockout."""

import bcrypt
import pytest
from fastapi.testclient import TestClient

from app import auth
from app.main import app

PASSWORD = "correct horse battery staple"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SITE_PASSWORD_HASH", bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(4)).decode())
    monkeypatch.setenv("SESSION_SECRET", "test-secret")
    auth._failures.clear()
    return TestClient(app, base_url="https://testserver")


def test_signed_out(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/api/meta").status_code == 401
    assert client.get("/api/lab/runs/x/events").status_code == 401
    assert client.get("/static/app.js", follow_redirects=False).status_code == 303
    assert client.get("/healthz").status_code == 200
    assert client.get("/static/style.css").status_code == 200
    r = client.get("/login")
    assert r.status_code == 200 and 'type="password"' in r.text and 'name="username"' not in r.text


def test_wrong_password(client):
    r = client.post("/login", data={"password": "nope"}, follow_redirects=False)
    assert r.status_code == 401 and "isn't right" in r.text and auth.COOKIE not in r.cookies


def test_sign_in(client):
    r = client.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    set_cookie = r.headers["set-cookie"].lower()
    assert "httponly" in set_cookie and "secure" in set_cookie and "samesite=lax" in set_cookie
    assert client.get("/").status_code == 200
    assert client.get("/api/meta").status_code == 200


def test_tampered_and_expired_cookies(client, monkeypatch):
    good = auth.issue()
    expiry, sig = good.split(".", 1)
    for bad in [f"{int(expiry) + 1}.{sig}", f"{expiry}.{'0' * len(sig)}", "garbage", ""]:
        client.cookies.set(auth.COOKIE, bad)
        assert client.get("/api/meta").status_code == 401
    monkeypatch.setattr(auth.time, "time", lambda: int(expiry) + 1)
    assert not auth.valid(good)


def test_password_change_signs_out(client, monkeypatch):
    cookie = auth.issue()
    monkeypatch.setenv("SITE_PASSWORD_HASH", bcrypt.hashpw(b"new", bcrypt.gensalt(4)).decode())
    assert not auth.valid(cookie)


def test_lockout(client):
    for _ in range(auth.FAIL_LIMIT):
        client.post("/login", data={"password": "nope"})
    r = client.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    assert r.status_code == 429 and auth.COOKIE not in r.cookies


def test_gate_off_without_hash(monkeypatch):
    monkeypatch.delenv("SITE_PASSWORD_HASH", raising=False)
    assert TestClient(app).get("/api/meta").status_code == 200
