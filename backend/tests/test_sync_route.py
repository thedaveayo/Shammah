"""
Tests for POST /api/sync, which the MCP server uses to download rules.
"""
import os
import sys
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import api.routes as routes  # noqa: E402
from database import Base  # noqa: E402
from models.rule import Rule  # noqa: E402


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)

    db = Session()
    old = datetime.utcnow() - timedelta(days=10)
    db.add_all([
        Rule(rule_id="DSV-2026-0001", rule_type="cwe", source="cwe", severity="high", title="Old rule",
             description="d", pattern={"type": "regex", "value": "eval\\(", "language": "javascript"},
             enforcement={"message": "m", "required_actions": ["a"]}, created_at=old, updated_at=old),
        Rule(rule_id="DSV-2026-0002", rule_type="dsv", source="telegram", severity="medium", title="New rule",
             description="d", pattern={"type": "regex", "value": "danger\\(", "language": "any"},
             enforcement={"message": "m", "required_actions": ["a"]}),
        Rule(rule_id="DSV-2026-0003", rule_type="cve", source="nvd", severity="low", title="No pattern",
             description="d", pattern=None, enforcement={"message": "m"}),
    ])
    db.commit()
    db.close()

    def get_test_db():
        session = Session()
        try:
            yield session
        finally:
            session.close()

    app = FastAPI()
    app.include_router(routes.router, prefix="/api")
    app.dependency_overrides[routes.get_db] = get_test_db
    return TestClient(app)


def test_sync_returns_rules_with_patterns(client):
    r = client.post("/api/sync", json={})
    assert r.status_code == 200
    body = r.json()
    ids = {rule["rule_id"] for rule in body["new_rules"]}
    assert ids == {"DSV-2026-0001", "DSV-2026-0002"}  # the rule without a pattern is skipped
    rule = next(x for x in body["new_rules"] if x["rule_id"] == "DSV-2026-0001")
    assert rule["pattern"]["value"] == "eval\\("
    assert rule["enforcement"]["required_actions"] == ["a"]
    assert body["total"] == 2 and body["synced_at"]


def test_sync_since_last_sync_only_returns_changes(client):
    since = (datetime.utcnow() - timedelta(days=1)).isoformat()
    r = client.post("/api/sync", json={"last_sync": since})
    assert {rule["rule_id"] for rule in r.json()["new_rules"]} == {"DSV-2026-0002"}


def test_sync_rejects_bad_timestamp(client):
    assert client.post("/api/sync", json={"last_sync": "yesterday"}).status_code == 400


def test_sync_needs_no_admin_key(client, monkeypatch):
    monkeypatch.setattr(routes, "ADMIN_API_KEY", "secret")
    assert client.post("/api/sync", json={}).status_code == 200
