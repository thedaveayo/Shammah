"""
SQLAlchemy Subscription Model
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from datetime import datetime, timedelta
from database import Base

class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, nullable=True)
    
    # Subscription status
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    
    # Auth token (JWT)
    auth_token = Column(String, unique=True, index=True, nullable=False)
    
    def is_valid(self):
        """Check if subscription is currently valid"""
        return datetime.utcnow() < self.expires_at
    
    def is_in_grace_period(self):
        """Check if subscription is in grace period (expired but within 7 days)"""
        if self.is_valid():
            return False
        grace_end = self.expires_at + timedelta(days=7)
        return datetime.utcnow() < grace_end
    
    def days_until_expiry(self):
        """Get days until subscription expires (negative if expired)"""
        delta = self.expires_at - datetime.utcnow()
        return delta.days
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            "user_id": self.user_id,
            "email": self.email,
            "is_active": self.is_active,
            "is_valid": self.is_valid(),
            "is_in_grace_period": self.is_in_grace_period(),
            "days_until_expiry": self.days_until_expiry(),
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat()
        }
