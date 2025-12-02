"""
Encryption Service for FortKnoxx Secrets Management
Uses Fernet (AES-256) for symmetric encryption
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os as os_module
import logging

logger = logging.getLogger(__name__)


class EncryptionService:
    """Handles encryption and decryption of sensitive data"""

    def __init__(self, master_key: str = None):
        """
        Initialize encryption service with a master key

        Args:
            master_key: Base64-encoded Fernet key. If None, generates or uses from env
        """
        if master_key:
            self.key = master_key.encode()
        else:
            # Try to get from environment
            env_key = os_module.getenv("ENCRYPTION_MASTER_KEY")
            if env_key:
                self.key = env_key.encode()
            else:
                # Generate a new key (in production, store this securely!)
                self.key = Fernet.generate_key()
                logger.warning(
                    "No master key found. Generated new key. "
                    "Store this securely: %s",
                    self.key.decode()
                )

        self.cipher = Fernet(self.key)

    @staticmethod
    def generate_key() -> str:
        """Generate a new Fernet encryption key"""
        return Fernet.generate_key().decode()

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """
        Derive an encryption key from a password using PBKDF2

        Args:
            password: User password
            salt: Salt bytes. If None, generates new salt

        Returns:
            Tuple of (key, salt)
        """
        if salt is None:
            salt = os_module.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext string

        Args:
            plaintext: String to encrypt

        Returns:
            Base64-encoded encrypted string
        """
        try:
            encrypted = self.cipher.encrypt(plaintext.encode())
            return encrypted.decode()
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise

    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypt encrypted string

        Args:
            encrypted_text: Base64-encoded encrypted string

        Returns:
            Decrypted plaintext string
        """
        try:
            decrypted = self.cipher.decrypt(encrypted_text.encode())
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise

    def encrypt_dict(self, data: dict) -> dict:
        """
        Encrypt all string values in a dictionary

        Args:
            data: Dictionary with string values

        Returns:
            Dictionary with encrypted values
        """
        encrypted_data = {}
        for key, value in data.items():
            if isinstance(value, str):
                encrypted_data[key] = self.encrypt(value)
            else:
                encrypted_data[key] = value
        return encrypted_data

    def decrypt_dict(self, encrypted_data: dict) -> dict:
        """
        Decrypt all encrypted values in a dictionary

        Args:
            encrypted_data: Dictionary with encrypted string values

        Returns:
            Dictionary with decrypted values
        """
        decrypted_data = {}
        for key, value in encrypted_data.items():
            if isinstance(value, str):
                try:
                    decrypted_data[key] = self.decrypt(value)
                except Exception:
                    # If decryption fails, might be unencrypted data
                    decrypted_data[key] = value
            else:
                decrypted_data[key] = value
        return decrypted_data

    @staticmethod
    def mask_secret(secret: str, visible_chars: int = 4) -> str:
        """
        Mask a secret for logging/display

        Args:
            secret: Secret string to mask
            visible_chars: Number of characters to show at end

        Returns:
            Masked string like "****abc123"
        """
        if len(secret) <= visible_chars:
            return "*" * len(secret)

        return "*" * (len(secret) - visible_chars) + secret[-visible_chars:]


# Lazy-loaded global encryption service instance
# This ensures load_dotenv() has run before we check for the key
_encryption_service = None


def get_encryption_service() -> EncryptionService:
    """Get the global encryption service instance (lazy initialization)"""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = EncryptionService()
    return _encryption_service


# For backward compatibility - but prefer get_encryption_service()
# Note: Direct use of this variable will still cause early instantiation
# when the module is first imported anywhere
class _LazyEncryptionService:
    """Proxy class that lazily creates the encryption service"""
    _instance = None

    def __getattr__(self, name):
        if _LazyEncryptionService._instance is None:
            _LazyEncryptionService._instance = EncryptionService()
        return getattr(_LazyEncryptionService._instance, name)


encryption_service = _LazyEncryptionService()
