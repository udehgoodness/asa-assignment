import hashlib
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
