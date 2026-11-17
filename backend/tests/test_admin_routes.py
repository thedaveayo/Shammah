"""
Tests for admin-key protection on routes that change data or call paid APIs.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import api.routes as routes  # noqa: E402

ADMIN_ROUTES = [
    ("post", "/api/fetch/cve"),
    ("post", "/api/fetch/cwe"),
    ("post", "/api/rules/telegram"),
    ("post", "/api/quick-fix/suggest"),
]


def make_client():
    app = FastAPI()
    app.include_router(routes.router, prefix="/api")
    return TestClient(app)


@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_admin_routes_disabled_without_key(monkeypatch, method, path):
    monkeypatch.setattr(routes, "ADMIN_API_KEY", "")
    r = getattr(make_client(), method)(path, headers={"Authorization": "Bearer anything"})
    assert r.status_code == 503


@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_admin_routes_reject_missing_key(monkeypatch, method, path):
    monkeypatch.setattr(routes, "ADMIN_API_KEY", "correct-key")
    r = getattr(make_client(), method)(path)
    assert r.status_code == 401


@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_admin_routes_reject_wrong_key(monkeypatch, method, path):
    monkeypatch.setattr(routes, "ADMIN_API_KEY", "correct-key")
    r = getattr(make_client(), method)(path, headers={"Authorization": "Bearer wrong-key"})
    assert r.status_code == 403


def test_admin_route_accepts_correct_key(monkeypatch):
    monkeypatch.setattr(routes, "ADMIN_API_KEY", "correct-key")

    class FakeFetcher:
        def sync_cwe_taxonomy(self, db, force=False):
            return 7

    monkeypatch.setattr(routes, "CWEFetcher", FakeFetcher)
    app = FastAPI()
    app.include_router(routes.router, prefix="/api")
    app.dependency_overrides[routes.get_db] = lambda: None
    r = TestClient(app).post("/api/fetch/cwe", headers={"Authorization": "Bearer correct-key"})
    assert r.status_code == 200
    assert r.json() == {"status": "success", "cwe_rules_saved": 7}


def test_removed_subscription_routes_are_gone():
    client = make_client()
    assert client.post("/api/auth/subscribe", json={"user_id": "x"}).status_code == 404
    assert client.get("/api/auth/status").status_code == 404
