"""
FastAPI Routes - Simplified Version
"""
from fastapi import APIRouter, Depends, HTTPException, Header, Query
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List, Optional, Dict
from database import get_db
from config import TOKEN_EXPIRE_DAYS
from services.rule_cache import RuleCache
from services.subscription import SubscriptionService
from services.advanced_auth_service import AdvancedAuthService, Role, Permission
from services.telegram_ingest import TelegramIngest
from services.export_generator import ExportGenerator
from services.cve_fetcher import CVEFetcher
from services.cwe_fetcher import CWEFetcher
from services.quick_fix_service import generate_quick_fix_suggestions
from api.schemas import TelegramIngestRequest, SubscriptionRequest

router = APIRouter()

@router.post("/auth/subscribe")
def create_subscription(request: SubscriptionRequest, db: Session = Depends(get_db)):
    """Create new subscription"""
    service = SubscriptionService()
    subscription = service.create_subscription(request.user_id, request.email)
    
    return {
        "user_id": subscription.user_id,
        "status": "active",
        "auth_token": subscription.auth_token,
        "expires_at": subscription.expires_at.isoformat(),
        "days_until_expiry": subscription.days_until_expiry()
    }

@router.get("/auth/status")
def check_subscription(authorization: Optional[str] = Header(None)):
    """Check subscription status"""
    if not authorization or not authorization.startswith("Bearer "):
        return {"status": "no_token"}
    
    token = authorization.replace("Bearer ", "")
    service = SubscriptionService()
    status = service.check_subscription_status(token)
    return status

@router.post("/rules/telegram")
def ingest_telegram(request: TelegramIngestRequest, db: Session = Depends(get_db)):
    """Ingest Telegram message (no auth required - trusted source)"""
    ingest = TelegramIngest()
    rule = ingest.process_message(request.message_text, request.message_date or datetime.utcnow().isoformat())
    
    if not rule:
        raise HTTPException(status_code=400, detail="Failed to extract rule")
    
    success = ingest.save_rule(rule, db)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save")
    
    # Regenerate export
    rule_cache = RuleCache(db)
    all_rules = rule_cache.get_all_rules()
    export_gen = ExportGenerator()
    export_gen.generate_and_save(all_rules)
    
    return {"status": "success", "rule_id": rule.rule_id}

@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Get rule statistics"""
    cache = RuleCache(db)
    return cache.get_rule_count()

@router.get("/public/rules")
def get_public_rules(db: Session = Depends(get_db)):
    """Get public export JSON (no auth required)"""
    cache = RuleCache(db)
    all_rules = cache.get_all_rules()
    export_gen = ExportGenerator()
    return export_gen.generate_export(all_rules)

@router.post("/fetch/cve")
def trigger_cve_fetch(db: Session = Depends(get_db)):
    """Manually trigger CVE fetch"""
    fetcher = CVEFetcher()
    saved = fetcher.sync_cves(db)
    return {"status": "success", "cves_saved": saved}

@router.post("/fetch/cwe")
def trigger_cwe_fetch(db: Session = Depends(get_db)):
    """Manually trigger CWE fetch"""
    fetcher = CWEFetcher()
    saved = fetcher.sync_cwe_taxonomy(db, force=False)
    return {"status": "success", "cwe_rules_saved": saved}

@router.post("/quick-fix/suggest")
def suggest_fixes(code: str, vulnerability_description: str, language: str = "javascript"):
    """Generate specific code fixes for security vulnerabilities"""
    fixes = generate_quick_fix_suggestions(code, vulnerability_description, language)
    
    if fixes is None:
        raise HTTPException(status_code=500, detail="Failed to generate fixes")
    
    return {
        "status": "success",
        "fixes": fixes
    }


# Subscription Management Endpoints
@router.post("/auth/register")
def register_user(user_id: str, email: str, password: str):
    """Register a new user with initial role"""
    auth_service = AdvancedAuthService()
    
    # In a real implementation, we'd hash the password
    user = auth_service.create_user(
        user_id=user_id,
        email=email,
        roles=[Role.DEVELOPER]  # Default role
    )
    
    return {
        "status": "success",
        "user_id": user.user_id,
        "email": user.email
    }


@router.post("/auth/login")
def login(user_id: str, password: str):
    """Authenticate user and return access token"""
    auth_service = AdvancedAuthService()
    
    user = auth_service.authenticate_user(user_id, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create access token
    access_token = auth_service.create_auth_token(user_id)
    
    return {
        "status": "success",
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": TOKEN_EXPIRE_DAYS * 24 * 60 * 60  # in seconds
    }


@router.get("/auth/me")
def get_current_user(authorization: Optional[str] = Header(None)):
    """Get current authenticated user info"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.replace("Bearer ", "")
    auth_service = AdvancedAuthService()
    user_info = auth_service.verify_token(token)
    
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    # In a real implementation, we'd fetch the full user details
    return {
        "user_id": user_info["user_id"],
        "permissions": user_info["permissions"]
    }


@router.get("/auth/permissions")
def get_user_permissions(authorization: Optional[str] = Header(None)):
    """Get current user's permissions"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.replace("Bearer ", "")
    auth_service = AdvancedAuthService()
    user_info = auth_service.verify_token(token)
    
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return {
        "permissions": user_info["permissions"]
    }


@router.post("/auth/revoke-token")
def revoke_token(authorization: Optional[str] = Header(None)):
    """Revoke the current access token"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.replace("Bearer ", "")
    auth_service = AdvancedAuthService()
    success = auth_service.revoke_token(token)
    
    if success:
        return {"status": "success", "message": "Token revoked successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to revoke token")


@router.get("/auth/users")
def list_users(authorization: Optional[str] = Header(None)):
    """List all users (admin only)"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.replace("Bearer ", "")
    auth_service = AdvancedAuthService()
    user_info = auth_service.verify_token(token)
    
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    if not auth_service.has_permission(token, Permission.MANAGE_USERS):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # In a real implementation, we'd return the list of users
    return {
        "users": [],  # Placeholder - would return actual user list
        "total_count": 0
    }


@router.put("/auth/users/{user_id}/roles")
def update_user_roles(user_id: str, roles: List[str], authorization: Optional[str] = Header(None)):
    """Update user roles (admin only)"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.replace("Bearer ", "")
    auth_service = AdvancedAuthService()
    
    if not auth_service.has_permission(token, Permission.MANAGE_USERS):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # In a real implementation, we'd update the user's roles
    return {
        "status": "success",
        "user_id": user_id,
        "roles": roles
    }
