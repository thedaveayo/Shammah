"""
Local Subscription Management
"""
import os
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models.subscription import LocalSubscription
from config import AUTH_TOKEN

class LocalSubscriptionManager:
    """Manages local subscription state"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def activate(self, auth_token: str, user_id: str) -> bool:
        """Activate subscription with auth token"""
        # Remove existing subscription
        self.db.query(LocalSubscription).delete()
        
        # Create new subscription
        subscription = LocalSubscription(
            user_id=user_id,
            auth_token=auth_token,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        self.db.add(subscription)
        self.db.commit()
        
        # Save token to .env file for persistence
        self._save_token_to_env(auth_token)
        
        return True
    
    def get_subscription(self) -> LocalSubscription:
        """Get current subscription"""
        return self.db.query(LocalSubscription).first()
    
    def update_expiry(self, expires_at: datetime):
        """Update subscription expiry (after sync)"""
        subscription = self.get_subscription()
        if subscription:
            subscription.expires_at = expires_at
            self.db.commit()
    
    def _save_token_to_env(self, token: str):
        """Save auth token to .env file"""
        env_path = ".env"
        
        # Read existing .env
        lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                lines = f.readlines()
        
        # Update or add AUTH_TOKEN
        token_line = f"AUTH_TOKEN={token}\n"
        found = False
        for i, line in enumerate(lines):
            if line.startswith("AUTH_TOKEN="):
                lines[i] = token_line
                found = True
                break
        
        if not found:
            lines.append(token_line)
        
        # Write back
        with open(env_path, 'w') as f:
            f.writelines(lines)
    
    def deactivate(self):
        """Deactivate subscription (logout)"""
        self.db.query(LocalSubscription).delete()
        self.db.commit()
        
        # Remove token from .env
        env_path = ".env"
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                lines = f.readlines()
            with open(env_path, 'w') as f:
                for line in lines:
                    if not line.startswith("AUTH_TOKEN="):
                        f.write(line)
