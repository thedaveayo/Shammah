"""
Subscription Validator Service
Handles validation of user subscriptions
"""
import jwt
import requests
from typing import Tuple, Dict, Any
from datetime import datetime, timedelta
import os
from config import BACKEND_URL, JWT_SECRET_KEY, JWT_ALGORITHM

class SubscriptionValidator:
    """Validates user subscriptions for access to security features"""
    
    def __init__(self):
        self.backend_url = os.getenv("BACKEND_URL", "http://localhost:8000")
        self.auth_token = os.getenv("AUTH_TOKEN")
    
    async def is_subscription_valid(self) -> bool:
        """
        Check if the current subscription is valid
        """
        try:
            status = await self.validate_subscription()
            return status[0]
        except Exception:
            return False
    
    async def validate_subscription(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate the current subscription
        Returns (is_valid, status_info)
        """
        if not self.auth_token:
            return False, {"message": "No authentication token provided"}
        
        try:
            # Decode the token to get user info
            payload = jwt.decode(self.auth_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")
            
            if not user_id:
                return False, {"message": "Invalid token: no user_id"}
            
            # Check subscription status with backend
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.get(f"{self.backend_url}/api/auth/status", headers=headers)
            
            if response.status_code == 200:
                status_data = response.json()
                status = status_data.get("status")
                
                if status == "active":
                    return True, {
                        "status": "active",
                        "days_until_expiry": status_data.get("days_until_expiry"),
                        "expires_at": status_data.get("expires_at")
                    }
                elif status == "grace_period":
                    return True, {
                        "status": "grace_period",
                        "days_remaining": status_data.get("days_remaining"),
                        "message": status_data.get("message")
                    }
                else:  # expired
                    return False, {
                        "status": "expired",
                        "message": status_data.get("message", "Subscription expired")
                    }
            else:
                return False, {"message": f"Backend validation failed: {response.status_code}"}
                
        except jwt.ExpiredSignatureError:
            return False, {"message": "Authentication token has expired"}
        except jwt.InvalidTokenError:
            return False, {"message": "Invalid authentication token"}
        except Exception as e:
            return False, {"message": f"Validation error: {str(e)}"}
    
    async def get_user_permissions(self) -> Dict[str, Any]:
        """
        Get the permissions associated with the current subscription
        """
        if not self.auth_token:
            return {"permissions": [], "error": "No authentication token provided"}
        
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.get(f"{self.backend_url}/api/auth/permissions", headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"permissions": [], "error": f"Failed to get permissions: {response.status_code}"}
                
        except Exception as e:
            return {"permissions": [], "error": f"Error getting permissions: {str(e)}"}