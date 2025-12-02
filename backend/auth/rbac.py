"""
Role-Based Access Control (RBAC) Manager for FortKnoxx
Handles permission checking and role-based access control
"""

from fastapi import HTTPException, Security, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import List, Optional
from .models import User, UserRole, TokenData
from .jwt_handler import jwt_handler
import logging

logger = logging.getLogger(__name__)

# Security scheme for FastAPI
security = HTTPBearer()


class RBACManager:
    """Manages role-based access control"""

    # Role hierarchy (higher roles have all permissions of lower roles)
    ROLE_HIERARCHY = {
        UserRole.ADMIN: 4,
        UserRole.SECURITY_LEAD: 3,
        UserRole.DEVELOPER: 2,
        UserRole.AUDITOR: 1,
    }

    # Permission matrix
    PERMISSIONS = {
        # User management
        "user:create": [UserRole.ADMIN],
        "user:update": [UserRole.ADMIN],
        "user:delete": [UserRole.ADMIN],
        "user:list": [UserRole.ADMIN, UserRole.SECURITY_LEAD],

        # Repository management
        "repo:create": [UserRole.ADMIN, UserRole.SECURITY_LEAD, UserRole.DEVELOPER],
        "repo:update": [UserRole.ADMIN, UserRole.SECURITY_LEAD, UserRole.DEVELOPER],
        "repo:delete": [UserRole.ADMIN, UserRole.SECURITY_LEAD],
        "repo:view": [UserRole.ADMIN, UserRole.SECURITY_LEAD, UserRole.DEVELOPER, UserRole.AUDITOR],

        # Scan operations
        "scan:start": [UserRole.ADMIN, UserRole.SECURITY_LEAD, UserRole.DEVELOPER],
        "scan:stop": [UserRole.ADMIN, UserRole.SECURITY_LEAD, UserRole.DEVELOPER],
        "scan:view": [UserRole.ADMIN, UserRole.SECURITY_LEAD, UserRole.DEVELOPER, UserRole.AUDITOR],
        "scan:delete": [UserRole.ADMIN, UserRole.SECURITY_LEAD],

        # Vulnerability operations
        "vuln:view": [UserRole.ADMIN, UserRole.SECURITY_LEAD, UserRole.DEVELOPER, UserRole.AUDITOR],
        "vuln:update": [UserRole.ADMIN, UserRole.SECURITY_LEAD, UserRole.DEVELOPER],
        "vuln:delete": [UserRole.ADMIN, UserRole.SECURITY_LEAD],

        # Report operations
        "report:view": [UserRole.ADMIN, UserRole.SECURITY_LEAD, UserRole.DEVELOPER, UserRole.AUDITOR],
        "report:export": [UserRole.ADMIN, UserRole.SECURITY_LEAD, UserRole.AUDITOR],
        "report:generate": [UserRole.ADMIN, UserRole.SECURITY_LEAD],

        # Settings and configuration
        "settings:view": [UserRole.ADMIN, UserRole.SECURITY_LEAD],
        "settings:update": [UserRole.ADMIN],

        # API keys and secrets
        "secrets:view": [UserRole.ADMIN],
        "secrets:update": [UserRole.ADMIN],
    }

    @classmethod
    def has_permission(cls, user_role: UserRole, permission: str) -> bool:
        """Check if a role has a specific permission"""
        allowed_roles = cls.PERMISSIONS.get(permission, [])
        return user_role in allowed_roles

    @classmethod
    def can_access_project(cls, user: User, repo_id: str) -> bool:
        """Check if user can access a specific project"""
        # Admins and Security Leads can access all projects
        if user.role in [UserRole.ADMIN, UserRole.SECURITY_LEAD]:
            return True

        # Other roles need explicit project access
        return repo_id in user.project_access

    @classmethod
    def role_level(cls, role: UserRole) -> int:
        """Get the hierarchy level of a role"""
        return cls.ROLE_HIERARCHY.get(role, 0)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db = None  # Will be injected via dependency
) -> User:
    """
    Dependency to get current user from JWT token
    Use this in FastAPI route dependencies
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        token = credentials.credentials
        payload = jwt_handler.verify_token(token)

        if payload is None:
            raise credentials_exception

        user_id: str = payload.get("user_id")
        email: str = payload.get("email")
        role: str = payload.get("role")

        if user_id is None or email is None:
            raise credentials_exception

        # In a real implementation, fetch user from database
        # For now, create a minimal user object from token
        user = User(
            id=user_id,
            email=email,
            username=email.split("@")[0],
            hashed_password="",  # Not needed from token
            role=UserRole(role)
        )

        return user

    except Exception as e:
        logger.error(f"Error getting current user: {str(e)}")
        raise credentials_exception


def require_role(allowed_roles: List[UserRole]):
    """
    Dependency factory to require specific roles
    Usage: @app.get("/admin", dependencies=[Depends(require_role([UserRole.ADMIN]))])
    """
    async def role_checker(
        current_user: User = Depends(get_current_user)
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {[r.value for r in allowed_roles]}"
            )
        return current_user

    return role_checker


def require_permission(permission: str):
    """
    Dependency factory to require specific permission
    Usage: @app.get("/scan", dependencies=[Depends(require_permission("scan:start"))])
    """
    async def permission_checker(
        current_user: User = Depends(get_current_user)
    ) -> User:
        if not RBACManager.has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission}"
            )
        return current_user

    return permission_checker


def require_project_access(repo_id: str):
    """
    Dependency factory to require project access
    Usage: @app.get("/repo/{repo_id}", dependencies=[Depends(require_project_access)])
    """
    async def project_access_checker(
        current_user: User = Depends(get_current_user)
    ) -> User:
        if not RBACManager.can_access_project(current_user, repo_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"No access to project: {repo_id}"
            )
        return current_user

    return project_access_checker
