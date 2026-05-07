"""
Subscription Service
Manages auth tokens and subscription validation
"""
import jwt
from datetime import datetime, timedelta
from typing import Optional
from config import JWT_SECRET_KEY, JWT_ALGORITHM, TOKEN_EXPIRE_DAYS
from models.subscription import Subscription
from database import SessionLocal

class SubscriptionService:
    """Manages user subscriptions and auth tokens"""
    
    def create_subscription(self, user_id: str, email: str = None) -> Subscription:
        """Create new subscription with auth token"""
        db = SessionLocal()
        
        # Check if user already has subscription
        existing = db.query(Subscription).filter(Subscription.user_id == user_id).first()
        if existing:
            db.close()
            return existing
        
        # Generate JWT token
        expires_at = datetime.utcnow() + timedelta(days=TOKEN_EXPIRE_DAYS)
        token_payload = {
            "user_id": user_id,
            "exp": expires_at,
            "iat": datetime.utcnow()
        }
        auth_token = jwt.encode(token_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        # Create subscription
        subscription = Subscription(
            user_id=user_id,
            email=email,
            is_active=True,
            expires_at=expires_at,
            auth_token=auth_token
        )
        
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
        db.close()
        
        return subscription
    
    def validate_token(self, token: str) -> Optional[Subscription]:
        """Validate auth token and return subscription"""
        try:
            # Decode and verify token
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")
            
            if not user_id:
                return None
            
            # Get subscription from database
            db = SessionLocal()
            subscription = db.query(Subscription).filter(
                Subscription.user_id == user_id,
                Subscription.auth_token == token
            ).first()
            db.close()
            
            return subscription
            
        except jwt.ExpiredSignatureError:
            # Token expired - subscription expired
            return None
        except jwt.InvalidTokenError:
            # Invalid token
            return None
    
    def check_subscription_status(self, token: str) -> Dict:
        """
        Check subscription status
        Returns: {status: "active"|"expired"|"grace_period", ...}
        """
        subscription = self.validate_token(token)
        
        if not subscription:
            return {
                "status": "expired",
                "message": "Invalid or expired token"
            }
        
        if subscription.is_valid():
            return {
                "status": "active",
                "days_until_expiry": subscription.days_until_expiry(),
                "expires_at": subscription.expires_at.isoformat()
            }
        
        if subscription.is_in_grace_period():
            days_in_grace = 7 - (datetime.utcnow() - subscription.expires_at).days
            return {
                "status": "grace_period",
                "days_remaining": days_in_grace,
                "message": f"Subscription expired. Grace period ends in {days_in_grace} days."
            }
        
        # Expired beyond grace period
        return {
            "status": "expired",
            "expired_at": subscription.expires_at.isoformat(),
            "message": "Subscription expired. Renew to continue receiving security updates."
        }
    
    def renew_subscription(self, user_id: str) -> Subscription:
        """Renew existing subscription (extend expiry)"""
        db = SessionLocal()
        
        subscription = db.query(Subscription).filter(Subscription.user_id == user_id).first()
        if not subscription:
            db.close()
            return self.create_subscription(user_id)
        
        # Extend expiry
        if subscription.is_valid():
            # Active subscription - extend from current expiry
            new_expiry = subscription.expires_at + timedelta(days=TOKEN_EXPIRE_DAYS)
        else:
            # Expired - extend from now
            new_expiry = datetime.utcnow() + timedelta(days=TOKEN_EXPIRE_DAYS)
        
        subscription.expires_at = new_expiry
        
        # Generate new token
        token_payload = {
            "user_id": user_id,
            "exp": new_expiry,
            "iat": datetime.utcnow()
        }
        subscription.auth_token = jwt.encode(token_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        db.commit()
        db.refresh(subscription)
        db.close()
        
        return subscription
