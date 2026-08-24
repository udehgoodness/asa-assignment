import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import models as app_models  # noqa: E402
from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Shared report link tests
# ---------------------------------------------------------------------------

def create_scan_for(token, title="Shared finding"):
    return client.post("/scans", json={
        "title": title,
        "severity": "high",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]


def extract_token_from_share_url(share_url):
    return share_url.rsplit("/share/", 1)[1]


def test_create_and_fetch_share_link_no_password():
    token = register_and_login()
    scan_id = create_scan_for(token)

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    assert resp.status_code == 201
    share_url = resp.json()["share_url"]
    assert "/share/" in share_url

    share_token = extract_token_from_share_url(share_url)
    fetch_resp = client.get(f"/share/{share_token}")
    assert fetch_resp.status_code == 200
    assert fetch_resp.json()["title"] == "Shared finding"
    assert "owner_id" not in fetch_resp.json()


def test_share_link_password_protected():
    token = register_and_login()
    scan_id = create_scan_for(token)

    resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "s3cret!"},
        headers=auth_headers(token),
    )
    share_token = extract_token_from_share_url(resp.json()["share_url"])

    no_pw_resp = client.get(f"/share/{share_token}")
    assert no_pw_resp.status_code == 401

    wrong_pw_resp = client.get(f"/share/{share_token}", params={"password": "wrong"})
    assert wrong_pw_resp.status_code == 401

    correct_pw_resp = client.get(f"/share/{share_token}", params={"password": "s3cret!"})
    assert correct_pw_resp.status_code == 200


def test_share_link_locks_after_max_failed_attempts():
    token = register_and_login()
    scan_id = create_scan_for(token)

    resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "correct-horse"},
        headers=auth_headers(token),
    )
    share_token = extract_token_from_share_url(resp.json()["share_url"])

    for _ in range(5):
        wrong_resp = client.get(f"/share/{share_token}", params={"password": "nope"})
        assert wrong_resp.status_code == 401

    locked_resp = client.get(f"/share/{share_token}", params={"password": "correct-horse"})
    assert locked_resp.status_code == 404


def test_non_owner_cannot_share_scan():
    owner_token = register_and_login(username="owner1", email="owner1@example.com")
    scan_id = create_scan_for(owner_token)

    other_token = register_and_login(username="intruder1", email="intruder1@example.com")
    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(other_token))
    assert resp.status_code == 404


def test_share_nonexistent_scan_returns_404():
    token = register_and_login()
    resp = client.post("/scans/999999/share", json={}, headers=auth_headers(token))
    assert resp.status_code == 404


def test_share_link_requires_auth():
    resp = client.post("/scans/1/share", json={})
    assert resp.status_code in (401, 403)


def test_expired_share_link_returns_404():
    token = register_and_login()
    scan_id = create_scan_for(token)

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_token = extract_token_from_share_url(resp.json()["share_url"])

    token_hash = hashlib.sha256(share_token.encode()).hexdigest()
    db = TestingSessionLocal()
    link = db.query(app_models.SharedLink).filter(
        app_models.SharedLink.token_hash == token_hash
    ).first()
    link.expires_at = datetime.utcnow() - timedelta(hours=1)
    db.commit()
    db.close()

    fetch_resp = client.get(f"/share/{share_token}")
    assert fetch_resp.status_code == 404


def test_unknown_share_token_returns_404():
    resp = client.get("/share/not-a-real-token")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Task 3 remediation regression tests
# ---------------------------------------------------------------------------

def _build_forged_none_alg_token(claims: dict) -> str:
    # jose.jwt.encode() itself refuses to build an alg=none token (it
    # checks against ALGORITHMS.SUPPORTED), so a real forged token has to
    # be hand-built exactly as an attacker would: base64url(header).base64url(payload).
    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url(json.dumps(claims).encode())
    return f"{header}.{payload}."


def test_jwt_none_algorithm_is_rejected():
    # VT-01: a forged token with alg=none and no signature must be cleanly
    # rejected with 401 (not silently accepted, and not an uncaught 500).
    forged_token = _build_forged_none_alg_token({"sub": "alice"})
    resp = client.get("/scans", headers=auth_headers(forged_token))
    assert resp.status_code == 401


def test_get_scan_by_id_is_owner_scoped():
    # VT-04: GET /scans/{id} must not return another user's scan.
    owner_token = register_and_login(username="owner2", email="owner2@example.com")
    scan_id = create_scan_for(owner_token, title="Owner-only finding")

    other_token = register_and_login(username="intruder2", email="intruder2@example.com")
    resp = client.get(f"/scans/{scan_id}", headers=auth_headers(other_token))
    assert resp.status_code == 404


def test_search_scans_is_owner_scoped():
    # VT-04: GET /scans/search must not return another user's scans.
    owner_token = register_and_login(username="owner3", email="owner3@example.com")
    create_scan_for(owner_token, title="Findable by owner3 only")

    other_token = register_and_login(username="intruder3", email="intruder3@example.com")
    resp = client.get("/scans/search?q=Findable", headers=auth_headers(other_token))
    assert resp.status_code == 200
    assert resp.json()["count"] == 0

    own_resp = client.get("/scans/search?q=Findable", headers=auth_headers(owner_token))
    assert own_resp.status_code == 200
    assert own_resp.json()["count"] == 1


def test_search_query_is_not_sql_injectable():
    # VT-02: a classic SQLi payload must not raise or leak other rows.
    token = register_and_login()
    create_scan_for(token, title="Safe finding")
    resp = client.get(
        "/scans/search",
        params={"q": "' OR '1'='1"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_oversized_register_password_rejected_cleanly():
    # VT-14: an oversized password must fail validation (422), not crash
    # into an unhandled 500 with a leaked stack trace.
    resp = client.post("/auth/register", json={
        "username": "toolong",
        "email": "toolong@example.com",
        "password": "a" * 100,
    })
    assert resp.status_code == 422


def test_oversized_share_password_rejected_cleanly():
    token = register_and_login()
    scan_id = create_scan_for(token)
    resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "a" * 100},
        headers=auth_headers(token),
    )
    assert resp.status_code == 422


def test_share_link_password_via_header():
    # VT-13: X-Share-Password header must work as an alternative to the
    # password query parameter.
    token = register_and_login()
    scan_id = create_scan_for(token)

    resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "header-pw"},
        headers=auth_headers(token),
    )
    share_token = extract_token_from_share_url(resp.json()["share_url"])

    header_resp = client.get(f"/share/{share_token}", headers={"X-Share-Password": "header-pw"})
    assert header_resp.status_code == 200

    wrong_header_resp = client.get(f"/share/{share_token}", headers={"X-Share-Password": "wrong"})
    assert wrong_header_resp.status_code == 401


def test_login_does_not_log_password(caplog):
    # VT-05: password must never appear in application logs.
    with caplog.at_level("INFO"):
        client.post("/auth/login", json={"username": "nouser", "password": "super-secret-pw"})
    assert "super-secret-pw" not in caplog.text
