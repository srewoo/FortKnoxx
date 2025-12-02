"""
Secrets Vault for FortKnoxx
Secure storage and retrieval of API keys, tokens, and credentials
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from enum import Enum
import uuid
import logging
from .encryption import encryption_service

logger = logging.getLogger(__name__)


class SecretType(str, Enum):
    """Types of secrets that can be stored"""
    GIT_TOKEN = "git_token"
    LLM_API_KEY = "llm_api_key"
    CLOUD_CREDENTIALS = "cloud_credentials"
    DATABASE_CREDENTIALS = "database_credentials"
    API_KEY = "api_key"
    WEBHOOK_SECRET = "webhook_secret"
    OTHER = "other"


class Secret(BaseModel):
    """Model for a stored secret"""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str  # User-friendly name
    type: SecretType
    encrypted_value: str  # The encrypted secret value
    description: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)  # Additional context

    # Ownership and permissions
    owner_id: str  # User who created the secret
    allowed_roles: List[str] = Field(default_factory=list)  # Roles that can access

    # Audit trail
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_accessed: Optional[datetime] = None
    access_count: int = 0

    # Security settings
    rotation_required: bool = False
    expires_at: Optional[datetime] = None


class SecretCreate(BaseModel):
    """Request to create a new secret"""
    name: str
    type: SecretType
    value: str  # Plaintext value (will be encrypted)
    description: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    allowed_roles: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None


class SecretResponse(BaseModel):
    """Response when retrieving secret (without value)"""
    id: str
    name: str
    type: SecretType
    description: Optional[str]
    metadata: Dict[str, Any]
    owner_id: str
    allowed_roles: List[str]
    created_at: datetime
    updated_at: datetime
    last_accessed: Optional[datetime]
    access_count: int
    rotation_required: bool
    expires_at: Optional[datetime]


class SecretsVault:
    """
    Manages encrypted storage and retrieval of secrets
    In production, this would integrate with a proper secrets management system
    like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault
    """

    def __init__(self, db=None, encryption_service_instance=None):
        """
        Initialize secrets vault

        Args:
            db: Database connection (MongoDB collection)
            encryption_service_instance: Encryption service to use
        """
        self.db = db
        self.encryption = encryption_service_instance or encryption_service

    async def store_secret(
        self,
        name: str,
        value: str,
        secret_type: SecretType,
        owner_id: str,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        allowed_roles: Optional[List[str]] = None,
        expires_at: Optional[datetime] = None
    ) -> Secret:
        """
        Store a new secret (encrypted)

        Args:
            name: User-friendly name for the secret
            value: Plaintext secret value
            secret_type: Type of secret
            owner_id: ID of user creating the secret
            description: Optional description
            metadata: Additional context
            allowed_roles: Roles allowed to access
            expires_at: Optional expiration date

        Returns:
            Created Secret object
        """
        try:
            # Encrypt the secret value
            encrypted_value = self.encryption.encrypt(value)

            secret = Secret(
                name=name,
                type=secret_type,
                encrypted_value=encrypted_value,
                description=description,
                metadata=metadata or {},
                owner_id=owner_id,
                allowed_roles=allowed_roles or [],
                expires_at=expires_at
            )

            # Store in database if available
            if self.db is not None:
                await self.db.insert_one(secret.model_dump())

            logger.info(
                f"Secret stored: {name} (type: {secret_type}, "
                f"masked: {self.encryption.mask_secret(value)})"
            )

            return secret

        except Exception as e:
            logger.error(f"Error storing secret: {str(e)}")
            raise

    async def get_secret(
        self,
        secret_id: str,
        user_id: str,
        user_role: str,
        decrypt: bool = True
    ) -> Optional[str]:
        """
        Retrieve and optionally decrypt a secret

        Args:
            secret_id: ID of the secret
            user_id: ID of requesting user
            user_role: Role of requesting user
            decrypt: Whether to decrypt the value

        Returns:
            Decrypted secret value or None if not found/not authorized
        """
        try:
            if self.db is None:
                logger.warning("No database configured for secrets vault")
                return None

            # Fetch from database
            secret_doc = await self.db.find_one({"id": secret_id})
            if not secret_doc:
                logger.warning(f"Secret not found: {secret_id}")
                return None

            secret = Secret(**secret_doc)

            # Check authorization
            if not self._check_access(secret, user_id, user_role):
                logger.warning(
                    f"Access denied to secret {secret_id} for user {user_id}"
                )
                return None

            # Update access tracking
            await self._update_access_tracking(secret_id)

            if decrypt:
                return self.encryption.decrypt(secret.encrypted_value)
            else:
                return secret.encrypted_value

        except Exception as e:
            logger.error(f"Error retrieving secret: {str(e)}")
            return None

    async def update_secret(
        self,
        secret_id: str,
        new_value: str,
        user_id: str,
        user_role: str
    ) -> bool:
        """
        Update a secret value (requires ownership or admin role)

        Args:
            secret_id: ID of the secret
            new_value: New plaintext value
            user_id: ID of requesting user
            user_role: Role of requesting user

        Returns:
            True if updated successfully
        """
        try:
            if self.db is None:
                return False

            secret_doc = await self.db.find_one({"id": secret_id})
            if not secret_doc:
                return False

            secret = Secret(**secret_doc)

            # Only owner or admin can update
            if secret.owner_id != user_id and user_role != "admin":
                logger.warning(f"Update denied for secret {secret_id}")
                return False

            # Encrypt new value
            encrypted_value = self.encryption.encrypt(new_value)

            # Update in database
            await self.db.update_one(
                {"id": secret_id},
                {
                    "$set": {
                        "encrypted_value": encrypted_value,
                        "updated_at": datetime.now(timezone.utc),
                        "rotation_required": False
                    }
                }
            )

            logger.info(f"Secret updated: {secret_id}")
            return True

        except Exception as e:
            logger.error(f"Error updating secret: {str(e)}")
            return False

    async def delete_secret(
        self,
        secret_id: str,
        user_id: str,
        user_role: str
    ) -> bool:
        """
        Delete a secret (requires ownership or admin role)

        Args:
            secret_id: ID of the secret
            user_id: ID of requesting user
            user_role: Role of requesting user

        Returns:
            True if deleted successfully
        """
        try:
            if self.db is None:
                return False

            secret_doc = await self.db.find_one({"id": secret_id})
            if not secret_doc:
                return False

            secret = Secret(**secret_doc)

            # Only owner or admin can delete
            if secret.owner_id != user_id and user_role != "admin":
                logger.warning(f"Delete denied for secret {secret_id}")
                return False

            await self.db.delete_one({"id": secret_id})
            logger.info(f"Secret deleted: {secret_id}")
            return True

        except Exception as e:
            logger.error(f"Error deleting secret: {str(e)}")
            return False

    async def list_secrets(
        self,
        user_id: str,
        user_role: str,
        secret_type: Optional[SecretType] = None
    ) -> List[SecretResponse]:
        """
        List secrets accessible to user (without decrypted values)

        Args:
            user_id: ID of requesting user
            user_role: Role of requesting user
            secret_type: Optional filter by secret type

        Returns:
            List of SecretResponse objects
        """
        try:
            if self.db is None:
                return []

            # Build query
            query = {}
            if secret_type:
                query["type"] = secret_type

            # Admins see all, others see only their own or allowed
            if user_role != "admin":
                query["$or"] = [
                    {"owner_id": user_id},
                    {"allowed_roles": {"$in": [user_role]}}
                ]

            secrets = []
            async for secret_doc in self.db.find(query):
                secret = Secret(**secret_doc)
                secrets.append(SecretResponse(
                    id=secret.id,
                    name=secret.name,
                    type=secret.type,
                    description=secret.description,
                    metadata=secret.metadata,
                    owner_id=secret.owner_id,
                    allowed_roles=secret.allowed_roles,
                    created_at=secret.created_at,
                    updated_at=secret.updated_at,
                    last_accessed=secret.last_accessed,
                    access_count=secret.access_count,
                    rotation_required=secret.rotation_required,
                    expires_at=secret.expires_at
                ))

            return secrets

        except Exception as e:
            logger.error(f"Error listing secrets: {str(e)}")
            return []

    def _check_access(
        self,
        secret: Secret,
        user_id: str,
        user_role: str
    ) -> bool:
        """Check if user has access to secret"""
        # Admins have access to everything
        if user_role == "admin":
            return True

        # Owner has access
        if secret.owner_id == user_id:
            return True

        # Check role-based access
        if user_role in secret.allowed_roles:
            return True

        return False

    async def _update_access_tracking(self, secret_id: str):
        """Update access tracking for a secret"""
        if self.db is not None:
            await self.db.update_one(
                {"id": secret_id},
                {
                    "$set": {"last_accessed": datetime.now(timezone.utc)},
                    "$inc": {"access_count": 1}
                }
            )
