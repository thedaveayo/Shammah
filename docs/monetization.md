# Monetization & Subscription Model

## Overview

Security MCP uses a subscription-based model:
- **$15/month** for full access
- Auth token-based validation
- 30-day token expiry
- 7-day grace period

---

## Subscription States

### 1. Active
- Token is valid (not expired)
- Full rule access
- Full enforcement (block on critical/high/medium)

### 2. Grace Period (0-7 days after expiry)
- Token expired but within 7 days
- Local cache still works
- Full enforcement continues
- Warning: "Subscription expired. Renew to continue receiving updates."

### 3. Expired (7+ days)
- Token expired beyond grace period
- No new rule syncs
- Vague warnings only (no fix details)
- User can proceed but feels unsafe

---

## User Flow

### New User
```
1. User installs MCP in IDE
2. Runs: security-mcp activate --token <token>
3. MCP syncs rules from backend
4. Full enforcement begins
```

### Subscription Expiry
```
Day 0:  Subscription expires
Day 1-7: Grace period - full functionality with warnings
Day 8+:  Expired - vague warnings, can proceed
```

### Renewal
```
1. User clicks "Renew" in IDE
2. Backend generates new token
3. MCP syncs with new token
4. Full access restored
```

---

## Technical Implementation

### Token Generation (Backend)
```python
import jwt
from datetime import datetime, timedelta

def create_token(user_id: str) -> str:
    expires_at = datetime.utcnow() + timedelta(days=30)
    payload = {
        "user_id": user_id,
        "exp": expires_at,
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")
```

### Token Validation (Backend)
```python
def validate_token(token: str) -> Optional[Subscription]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload["user_id"]
        # Get subscription from DB
        return subscription
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token
```

### Rule Expiry (Enforcement)
```python
# Rules have expires_at field
# MCP checks before enforcing

def is_rule_valid(rule: Rule) -> bool:
    if not rule.expires_at:
        return True
    return datetime.utcnow() < rule.expires_at
```

---

## Pricing Tiers (Future)

### Free Tier
- 10 rules/day
- Community rules only
- No DSV rules

### Pro ($15/month)
- Unlimited enforcement
- Full DSV library
- Priority support

### Enterprise (Custom)
- Self-hosted backend
- Custom rule creation
- SLA support

---

## Revenue Protection

### Preventing Bypass

1. **Token Validation on Every Sync**
   - MCP validates token with backend on each sync
   - Expired token = no new rules

2. **Rule Expiry**
   - Rules have `expires_at` field
   - Old rules become unenforceable after 30 days
   - Forces renewal for continued protection

3. **No Offline Cracking**
   - Rules are useless without MCP
   - MCP requires valid token
   - Export JSON is sanitized (no fix details)

---

## Metrics to Track

| Metric | Purpose |
|--------|---------|
| Active subscriptions | Revenue tracking |
| Churn rate | Product health |
| Renewal rate | Customer satisfaction |
| Grace period conversions | Urgency effectiveness |

---

## Integration with Stripe (Future)

```python
import stripe

def create_checkout_session(user_id: str):
    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{
            "price": "price_xxx",  # $15/month
            "quantity": 1
        }],
        mode="subscription",
        success_url="https://security-mcp.com/success?session_id={CHECKOUT_SESSION_ID}",
        cancel_url="https://security-mcp.com/pricing"
    )
    return session
```

---

## Cancellation Flow

```
1. User cancels subscription
2. Backend marks subscription as cancelled
3. Token remains valid until end of billing period
4. After expiry: grace period → expired state
5. Data retained for 90 days (re-activation)
```
