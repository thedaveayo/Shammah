"""
Local Subscription Model
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from datetime import datetime, timedelta
from database import Base

class LocalSubscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, unique=True, nullable=False)
    auth_token = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    last_sync = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def is_valid(self):
        """Check if subscription is currently valid"""
        if not self.expires_at:
            return False
        return datetime.utcnow() < self.expires_at
    
    def is_in_grace_period(self):
        """Check if in grace period after expiry"""
        if self.is_valid():
            return False
        if not self.expires_at:
            return False
        grace_end = self.expires_at + timedelta(days=7)
        return datetime.utcnow() < grace_end
