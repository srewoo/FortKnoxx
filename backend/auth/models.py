"""
Authentication Models for FortKnoxx
"""

from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List
from datetime import datetime, timezone
from enum import Enum
import uuid


class UserRole(str, Enum):
    """User roles with hierarchical permissions"""
    ADMIN = "admin"                    # Full access, user management
    SECURITY_LEAD = "security_lead"    # Manage scans, view all reports
    DEVELOPER = "developer"            # Run scans, view own reports
    AUDITOR = "auditor"                # Read-only access to all reports


class User(BaseModel):
    """User model with RBAC support"""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    username: str
    hashed_password: str
    role: UserRole = UserRole.DEVELOPER
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Per-project access control
    project_access: List[str] = Field(default_factory=list)  # List of repo IDs

    # Session management
    last_login: Optional[datetime] = None
    session_timeout_minutes: int = 480  # 8 hours default


class UserCreate(BaseModel):
    """User creation request"""
    email: EmailStr
    username: str
    password: str
    role: UserRole = UserRole.DEVELOPER


class UserLogin(BaseModel):
    """User login request"""
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """JWT token response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: dict  # Basic user info (id, email, username, role)


class TokenData(BaseModel):
    """Token payload data"""
    user_id: str
    email: str
    role: UserRole
    exp: datetime
