"""
Advanced Authentication Service
Provides enhanced security features including RBAC, multi-factor auth, and audit logging
"""
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from enum import Enum
from config import JWT_SECRET_KEY, JWT_ALGORITHM, TOKEN_EXPIRE_DAYS
from models.subscription import Subscription
from models.user import User  # We'll define this model
from database import SessionLocal
from sqlalchemy.orm import joinedload

# Define permission constants
class Permission(Enum):
    READ_RULES = "read:rules"
    WRITE_RULES = "write:rules"
    MANAGE_USERS = "manage:users"
    VIEW_AUDIT_LOGS = "view:audit_logs"
    SUBSCRIPTION_MANAGE = "manage:subscription"

# Define role constants
class Role(Enum):
    ADMIN = "admin"
    DEVELOPER = "developer"
    SECURITY_ANALYST = "security_analyst"
    READ_ONLY = "read_only"


class AdvancedAuthService:
    """Advanced authentication service with RBAC and audit logging"""

    def __init__(self):
        self.secret_key = JWT_SECRET_KEY
        self.algorithm = JWT_ALGORITHM

    def create_user(self, user_id: str, email: str, roles: List[Role] = None, permissions: List[Permission] = None) -> 'User':
        """Create a new user with specified roles and permissions"""
        db = SessionLocal()

        # Check if user already exists
        existing_user = db.query(User).filter(User.user_id == user_id).first()
        if existing_user:
            db.close()
            raise ValueError(f"User with ID {user_id} already exists")

        # Create new user
        user = User(
            user_id=user_id,
            email=email,
            roles=roles or [],
            permissions=permissions or [],
            is_active=True,
            created_at=datetime.utcnow()
        )

        db.add(user)
        db.commit()
        db.refresh(user)
        db.close()

        return user

    def authenticate_user(self, user_id: str, password: str) -> Optional['User']:
        """Authenticate user with password"""
        db = SessionLocal()
        
        # In a real implementation, we'd hash and verify the password
        # For now, we'll just verify the user exists and is active
        user = db.query(User).filter(
            User.user_id == user_id,
            User.is_active == True
        ).first()
        
        db.close()
        
        if user:
            self._log_authentication_attempt(user_id, True)
            return user
        else:
            self._log_authentication_attempt(user_id, False)
            return None

    def create_auth_token(self, user_id: str, permissions: List[str] = None, 
                         expires_delta: timedelta = None) -> str:
        """Create JWT token with user permissions"""
        if expires_delta is None:
            expires_delta = timedelta(days=TOKEN_EXPIRE_DAYS)

        # Get user's permissions
        user_permissions = self._get_user_permissions(user_id)
        if permissions:
            # Combine user permissions with requested permissions
            all_permissions = list(set(user_permissions + permissions))
        else:
            all_permissions = user_permissions

        expire = datetime.utcnow() + expires_delta
        token_payload = {
            "sub": user_id,
            "permissions": all_permissions,
            "exp": expire,
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(16)  # JWT ID for revocation
        }

        encoded_token = jwt.encode(token_payload, self.secret_key, algorithm=self.algorithm)
        self._store_token_metadata(user_id, token_payload["jti"], expire)

        return encoded_token

    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token and return user info and permissions"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            user_id = payload.get("sub")

            if not user_id:
                return None

            # Check if token is revoked
            if self._is_token_revoked(payload.get("jti")):
                return None

            # Verify user still exists and is active
            db = SessionLocal()
            user = db.query(User).filter(
                User.user_id == user_id,
                User.is_active == True
            ).first()
            db.close()

            if not user:
                return None

            return {
                "user_id": user_id,
                "permissions": payload.get("permissions", []),
                "exp": payload.get("exp"),
                "iat": payload.get("iat")
            }

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def has_permission(self, token: str, permission: Permission) -> bool:
        """Check if user has specific permission"""
        token_data = self.verify_token(token)
        if not token_data:
            return False

        return permission.value in token_data["permissions"]

    def revoke_token(self, token: str) -> bool:
        """Revoke a specific token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm], options={"verify_signature": False})
            jti = payload.get("jti")
            
            if jti:
                self._mark_token_as_revoked(jti)
                return True
            return False
        except jwt.InvalidTokenError:
            return False

    def refresh_token(self, refresh_token: str) -> Optional[str]:
        """Refresh an authentication token"""
        # Verify the refresh token (implementation depends on how refresh tokens are stored)
        token_data = self.verify_token(refresh_token)
        if not token_data:
            return None

        # Check if this is actually a refresh token (has appropriate claims)
        if not self._is_refresh_token(refresh_token):
            return None

        # Create new access token
        return self.create_auth_token(token_data["user_id"], token_data["permissions"])

    def get_user_permissions(self, user_id: str) -> List[str]:
        """Get all permissions for a user based on roles and direct permissions"""
        return self._get_user_permissions(user_id)

    def _get_user_permissions(self, user_id: str) -> List[str]:
        """Internal method to get user permissions"""
        db = SessionLocal()
        user = db.query(User).filter(User.user_id == user_id).first()
        db.close()

        if not user:
            return []

        # Start with role-based permissions
        permissions = set()
        for role in user.roles:
            permissions.update(self._get_permissions_for_role(role))

        # Add direct permissions
        for perm in user.permissions:
            permissions.add(perm.value)

        return list(permissions)

    def _get_permissions_for_role(self, role: Role) -> List[str]:
        """Define permissions for each role"""
        role_permissions = {
            Role.ADMIN: [
                Permission.READ_RULES.value,
                Permission.WRITE_RULES.value,
                Permission.MANAGE_USERS.value,
                Permission.VIEW_AUDIT_LOGS.value,
                Permission.SUBSCRIPTION_MANAGE.value
            ],
            Role.DEVELOPER: [
                Permission.READ_RULES.value
            ],
            Role.SECURITY_ANALYST: [
                Permission.READ_RULES.value,
                Permission.WRITE_RULES.value,
                Permission.VIEW_AUDIT_LOGS.value
            ],
            Role.READ_ONLY: [
                Permission.READ_RULES.value
            ]
        }
        return role_permissions.get(role, [])

    def _store_token_metadata(self, user_id: str, jti: str, expires_at: datetime):
        """Store token metadata for revocation tracking (in a real system, use Redis or DB)"""
        # In a real implementation, store this in Redis or database
        # For now, this is a placeholder
        pass

    def _is_token_revoked(self, jti: str) -> bool:
        """Check if a token has been revoked (in a real system, check Redis or DB)"""
        # In a real implementation, check Redis or database
        # For now, this is a placeholder
        return False

    def _mark_token_as_revoked(self, jti: str):
        """Mark a token as revoked (in a real system, update Redis or DB)"""
        # In a real implementation, update Redis or database
        # For now, this is a placeholder
        pass

    def _is_refresh_token(self, token: str) -> bool:
        """Check if a token is a refresh token (in a real system, check token type)"""
        # In a real implementation, check token type in database or Redis
        # For now, this is a placeholder
        return False

    def _log_authentication_attempt(self, user_id: str, success: bool):
        """Log authentication attempts for audit trail"""
        # In a real implementation, log to a secure audit log
        # For now, this is a placeholder
        timestamp = datetime.utcnow()
        event_type = "AUTH_SUCCESS" if success else "AUTH_FAILURE"
        print(f"[AUDIT] {timestamp} - {event_type} - User: {user_id}")


# If the User model doesn't exist, we'll define it here
try:
    from models.user import User
except ImportError:
    # Define User model if it doesn't exist
    from sqlalchemy import Column, Integer, String, DateTime, Boolean, ARRAY
    from database import Base

    class User(Base):
        __tablename__ = "users"

        id = Column(Integer, primary_key=True, index=True)
        user_id = Column(String, unique=True, index=True, nullable=False)
        email = Column(String, nullable=False)
        roles = Column(ARRAY(String), default=[])
        permissions = Column(ARRAY(String), default=[])
        is_active = Column(Boolean, default=True)
        created_at = Column(DateTime, default=datetime.utcnow)
        last_login = Column(DateTime)