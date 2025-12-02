"""
Settings Manager for FortKnoxx
Handles storage and retrieval of configuration settings with encryption
"""

import os
from typing import Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
import logging

from .models import (
    Setting, SettingCategory, APIKeySetting, SettingsResponse,
    ScannerSettings, UpdateScannerSettingsRequest
)

logger = logging.getLogger(__name__)


class SettingsManager:
    """Manages application settings with MongoDB storage and encryption"""

    def __init__(self, db: AsyncIOMotorDatabase = None, encryption_service=None):
        """
        Initialize settings manager

        Args:
            db: MongoDB database instance
            encryption_service: Optional encryption service for sensitive data
        """
        self.db = db
        self.encryption_service = encryption_service
        self.collection_name = "settings"
        self._cache: Dict[str, Any] = {}

    def set_db(self, db: AsyncIOMotorDatabase):
        """Set the database connection"""
        self.db = db

    def set_encryption(self, encryption_service):
        """Set the encryption service"""
        self.encryption_service = encryption_service

    async def get_setting(self, category: SettingCategory, key: str, default: Any = None) -> Any:
        """
        Get a setting value

        Args:
            category: Setting category
            key: Setting key
            default: Default value if not found

        Returns:
            Setting value or default
        """
        try:
            cache_key = f"{category}:{key}"

            # Check cache first
            if cache_key in self._cache:
                return self._cache[cache_key]

            # Check environment variable first (backwards compatibility)
            env_value = os.getenv(key.upper())
            if env_value:
                self._cache[cache_key] = env_value
                return env_value

            # Query database
            if self.db is None:
                return default

            setting = await self.db[self.collection_name].find_one({
                "category": category,
                "key": key
            })

            if setting is None:
                return default

            value = setting["value"]

            # Decrypt if needed
            if setting.get("encrypted", False) and self.encryption_service:
                try:
                    value = self.encryption_service.decrypt(value)
                except Exception as e:
                    logger.error(f"Failed to decrypt setting {key}: {str(e)}")
                    return default

            # Cache the result
            self._cache[cache_key] = value
            return value

        except Exception as e:
            logger.error(f"Error getting setting {category}:{key}: {str(e)}")
            return default

    async def set_setting(
        self,
        category: SettingCategory,
        key: str,
        value: Any,
        encrypt: bool = True,
        updated_by: Optional[str] = None
    ):
        """
        Set a setting value

        Args:
            category: Setting category
            key: Setting key
            value: Setting value
            encrypt: Whether to encrypt the value
            updated_by: User who is updating the setting
        """
        try:
            if self.db is None:
                raise ValueError("Database not initialized")

            # Encrypt if needed
            stored_value = value
            if encrypt and self.encryption_service and value:
                stored_value = self.encryption_service.encrypt(str(value))

            setting = Setting(
                category=category,
                key=key,
                value=stored_value,
                encrypted=encrypt,
                updated_by=updated_by
            )

            # Upsert to database
            await self.db[self.collection_name].update_one(
                {"category": category, "key": key},
                {"$set": setting.model_dump()},
                upsert=True
            )

            # Update cache
            cache_key = f"{category}:{key}"
            self._cache[cache_key] = value

            logger.info(f"Setting {category}:{key} updated successfully")

        except Exception as e:
            logger.error(f"Error setting {category}:{key}: {str(e)}")
            raise

    async def delete_setting(self, category: SettingCategory, key: str):
        """
        Delete a setting

        Args:
            category: Setting category
            key: Setting key
        """
        try:
            if self.db is None:
                raise ValueError("Database not initialized")

            await self.db[self.collection_name].delete_one({
                "category": category,
                "key": key
            })

            # Clear cache
            cache_key = f"{category}:{key}"
            if cache_key in self._cache:
                del self._cache[cache_key]

            logger.info(f"Setting {category}:{key} deleted")

        except Exception as e:
            logger.error(f"Error deleting setting {category}:{key}: {str(e)}")
            raise

    async def get_all_settings(self) -> SettingsResponse:
        """
        Get all settings (without values, just status)

        Returns:
            SettingsResponse with setting availability
        """
        try:
            response = SettingsResponse()

            # Check LLM API keys
            api_keys = [
                "openai_api_key",
                "anthropic_api_key",
                "gemini_api_key",
                "github_token",
                "snyk_token"
            ]

            for key in api_keys:
                value = await self.get_setting(SettingCategory.LLM_API_KEYS, key)
                response.llm_api_keys[key] = bool(value)

            # Get AI scanner settings (deprecated, kept for backwards compatibility)
            ai_scanner_settings = await self.get_ai_scanner_settings()
            response.ai_scanner_settings = ai_scanner_settings

            # Get full scanner settings
            scanner_settings = await self.get_scanner_settings()
            response.scanner_settings = scanner_settings

            return response

        except Exception as e:
            logger.error(f"Error getting all settings: {str(e)}")
            return SettingsResponse()

    async def update_api_keys(self, api_keys: APIKeySetting, updated_by: Optional[str] = None):
        """
        Update API keys

        Args:
            api_keys: APIKeySetting model with keys to update
            updated_by: User updating the keys
        """
        try:
            key_mapping = {
                "openai_api_key": api_keys.openai_api_key,
                "anthropic_api_key": api_keys.anthropic_api_key,
                "gemini_api_key": api_keys.gemini_api_key,
                "github_token": api_keys.github_token,
                "snyk_token": api_keys.snyk_token
            }

            for key, value in key_mapping.items():
                if value is not None and value.strip():  # Only update if provided
                    await self.set_setting(
                        category=SettingCategory.LLM_API_KEYS,
                        key=key,
                        value=value,
                        encrypt=True,
                        updated_by=updated_by
                    )
                elif value == "":  # Empty string means delete
                    await self.delete_setting(SettingCategory.LLM_API_KEYS, key)

            logger.info("API keys updated successfully")

        except Exception as e:
            logger.error(f"Error updating API keys: {str(e)}")
            raise

    async def get_api_keys(self) -> Dict[str, Optional[str]]:
        """
        Get all API keys (decrypted)

        Returns:
            Dictionary of API keys
        """
        try:
            keys = {}
            api_key_names = [
                "openai_api_key",
                "anthropic_api_key",
                "gemini_api_key",
                "github_token",
                "snyk_token"
            ]

            for key in api_key_names:
                value = await self.get_setting(SettingCategory.LLM_API_KEYS, key)
                keys[key] = value

            return keys

        except Exception as e:
            logger.error(f"Error getting API keys: {str(e)}")
            return {}

    async def get_ai_scanner_settings(self) -> Dict[str, bool]:
        """
        Get AI scanner settings

        Returns:
            Dictionary of AI scanner enable/disable states
        """
        try:
            settings = {
                "enable_zero_day_detector": True,  # Default to enabled
                "enable_business_logic_scanner": True,
                "enable_llm_security_scanner": True,
                "enable_auth_scanner": True  # Now enabled by default
            }

            for key in settings.keys():
                value = await self.get_setting(
                    SettingCategory.SCANNER_CONFIG,
                    key,
                    default=settings[key]
                )
                # Convert to boolean
                if isinstance(value, str):
                    settings[key] = value.lower() in ('true', '1', 'yes', 'enabled')
                else:
                    settings[key] = bool(value)

            return settings

        except Exception as e:
            logger.error(f"Error getting AI scanner settings: {str(e)}")
            return {
                "enable_zero_day_detector": True,
                "enable_business_logic_scanner": True,
                "enable_llm_security_scanner": True,
                "enable_auth_scanner": True
            }

    async def update_ai_scanner_settings(self, settings: Dict[str, bool]) -> bool:
        """
        Update AI scanner settings

        Args:
            settings: Dictionary of AI scanner enable/disable states

        Returns:
            True if successful
        """
        try:
            for key, value in settings.items():
                if key in [
                    "enable_zero_day_detector",
                    "enable_business_logic_scanner",
                    "enable_llm_security_scanner",
                    "enable_auth_scanner"
                ]:
                    await self.set_setting(
                        SettingCategory.SCANNER_CONFIG,
                        key,
                        value,
                        encrypt=False  # No need to encrypt boolean flags
                    )

            logger.info("AI scanner settings updated successfully")
            return True

        except Exception as e:
            logger.error(f"Error updating AI scanner settings: {str(e)}")
            return False

    def clear_cache(self):
        """Clear the settings cache"""
        self._cache.clear()
        logger.info("Settings cache cleared")

    async def get_scanner_settings(self) -> ScannerSettings:
        """
        Get all scanner enable/disable settings

        Returns:
            ScannerSettings with current state of all scanners
        """
        try:
            # Default settings (all enabled except those requiring setup)
            defaults = ScannerSettings()
            settings_dict = {}

            # Get all scanner setting keys from the model
            for field_name, field_info in ScannerSettings.model_fields.items():
                # Get from database or use default
                value = await self.get_setting(
                    SettingCategory.SCANNER_CONFIG,
                    field_name,
                    default=getattr(defaults, field_name)
                )

                # Convert to boolean
                if isinstance(value, str):
                    settings_dict[field_name] = value.lower() in ('true', '1', 'yes', 'enabled')
                else:
                    settings_dict[field_name] = bool(value)

            return ScannerSettings(**settings_dict)

        except Exception as e:
            logger.error(f"Error getting scanner settings: {str(e)}")
            # Return defaults on error
            return ScannerSettings()

    async def update_scanner_settings(
        self,
        updates: UpdateScannerSettingsRequest,
        updated_by: Optional[str] = None
    ) -> ScannerSettings:
        """
        Update scanner enable/disable settings

        Args:
            updates: UpdateScannerSettingsRequest with fields to update
            updated_by: User updating the settings

        Returns:
            Updated ScannerSettings
        """
        try:
            # Get current settings
            current_settings = await self.get_scanner_settings()

            # Update only provided fields
            update_dict = updates.model_dump(exclude_unset=True)

            for key, value in update_dict.items():
                if value is not None:
                    # Save to database
                    await self.set_setting(
                        SettingCategory.SCANNER_CONFIG,
                        key,
                        value,
                        encrypt=False,  # No need to encrypt boolean flags
                        updated_by=updated_by
                    )
                    # Update current settings object
                    setattr(current_settings, key, value)

            logger.info(f"Scanner settings updated: {len(update_dict)} changes")
            return current_settings

        except Exception as e:
            logger.error(f"Error updating scanner settings: {str(e)}")
            raise


# Global settings manager instance
settings_manager = SettingsManager()
