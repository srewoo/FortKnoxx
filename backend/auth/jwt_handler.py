"""
JWT Token Handler for FortKnoxx
Handles token generation, validation, and revocation
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
import logging

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class JWTHandler:
    """Handles JWT token operations"""

    def __init__(
        self,
        secret_key: Optional[str] = None,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 480  # 8 hours
    ):
        self.secret_key = secret_key or os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes

        # Token revocation list (in production, use Redis)
        self.revoked_tokens = set()

    def create_access_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a new JWT access token"""
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes)

        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "access"
        })

        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode a JWT token"""
        try:
            # Check if token is revoked
            if token in self.revoked_tokens:
                logger.warning("Attempted use of revoked token")
                return None

            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            # Check expiration
            exp = payload.get("exp")
            if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
                logger.warning("Token has expired")
                return None

            return payload

        except JWTError as e:
            logger.error(f"JWT verification error: {str(e)}")
            return None

    def revoke_token(self, token: str) -> bool:
        """Revoke a token (add to blacklist)"""
        try:
            self.revoked_tokens.add(token)
            logger.info("Token revoked successfully")
            return True
        except Exception as e:
            logger.error(f"Error revoking token: {str(e)}")
            return False

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt"""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)

    def create_user_token(
        self,
        user_id: str,
        email: str,
        role: str,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a token for a user with their details"""
        token_data = {
            "user_id": user_id,
            "email": email,
            "role": role
        }
        return self.create_access_token(token_data, expires_delta)


# Global JWT handler instance
jwt_handler = JWTHandler()
