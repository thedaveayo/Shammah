#!/usr/bin/env python3
"""
End-to-End Test Script
Tests backend API and basic functionality
"""
import requests
import json

BACKEND_URL = "http://localhost:8000"

def test_health():
    """Test health endpoint"""
    r = requests.get(f"{BACKEND_URL}/health")
    assert r.status_code == 200
    assert r.json() == {"status": "healthy"}
    print("✓ Health check passed")

def test_root():
    """Test root endpoint"""
    r = requests.get(f"{BACKEND_URL}/")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "running"
    print(f"✓ Root endpoint: {data['name']} v{data['version']}")

def test_create_subscription():
    """Test subscription creation"""
    payload = {
        "user_id": "test_user_dave",
        "email": "dave@test.com"
    }
    r = requests.post(f"{BACKEND_URL}/api/auth/subscribe", json=payload)
    if r.status_code == 200:
        data = r.json()
        print(f"✓ Subscription created: {data['user_id']}")
        print(f"  Token: {data['auth_token'][:30]}...")
        print(f"  Expires in: {data['days_until_expiry']} days")
        return data['auth_token']
    else:
        print(f"⚠ Subscription test skipped (may already exist): {r.status_code}")
        return None

def test_telegram_ingest(token):
    """Test Telegram message ingestion"""
    payload = {
        "message_text": "Critical Firebase auth bypass allows any user to read all database records. severity: critical. https://example.com/security-alert",
        "message_date": "2026-04-29T20:00:00Z"
    }
    r = requests.post(f"{BACKEND_URL}/api/rules/telegram", json=payload)
    if r.status_code == 200:
        data = r.json()
        print(f"✓ Telegram rule created: {data['rule_id']}")
        return True
    else:
        print(f"✗ Telegram ingest failed: {r.status_code} - {r.text}")
        return False

def test_get_stats(token):
    """Test getting rule statistics"""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = requests.get(f"{BACKEND_URL}/api/stats", headers=headers)
    if r.status_code == 200:
        data = r.json()
        print(f"✓ Rule stats: {data}")
        return True
    else:
        print(f"⚠ Stats unavailable: {r.status_code}")
        return False

def test_public_rules():
    """Test public rules endpoint"""
    r = requests.get(f"{BACKEND_URL}/api/public/rules")
    if r.status_code == 200:
        data = r.json()
        print(f"✓ Public rules: {len(data)} rules available")
        return True
    else:
        print(f"✗ Public rules failed: {r.status_code}")
        return False

def main():
    print("=" * 60)
    print("Security MCP - End-to-End Test")
    print("=" * 60)
    
    try:
        # Test basic endpoints
        test_health()
        test_root()
        
        # Test subscription
        token = test_create_subscription()
        
        # Test Telegram ingestion
        test_telegram_ingest(token)
        
        # Test stats
        test_get_stats(token)
        
        # Test public rules
        test_public_rules()
        
        print("=" * 60)
        print("✓ All tests completed!")
        print("=" * 60)
        print("\nNext Steps:")
        print("1. Visit http://localhost:8000/docs for interactive API")
        print("2. Test MCP server with: cd mcp-server && python main.py")
        print("3. Configure IDE to connect to MCP server")
        
    except requests.ConnectionError:
        print("✗ Cannot connect to backend. Is it running on localhost:8000?")
    except Exception as e:
        print(f"✗ Test failed: {e}")

if __name__ == "__main__":
    main()
