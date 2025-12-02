"""
Scheduled Model Update Service
Periodically checks for and downloads new model versions

Features:
- Background scheduler for periodic updates
- Version comparison to avoid unnecessary downloads
- Graceful model hot-swapping without restart
- Rollback support if new model fails validation
- Configurable update sources (local, HTTP, S3)
"""

import os
import json
import asyncio
import logging
import hashlib
import shutil
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp

logger = logging.getLogger(__name__)


class UpdateSource(Enum):
    """Supported model update sources"""
    LOCAL = "local"  # Local directory (for testing/dev)
    HTTP = "http"  # HTTP/HTTPS URL
    S3 = "s3"  # AWS S3 bucket
    GCS = "gcs"  # Google Cloud Storage


@dataclass
class ModelVersion:
    """Model version metadata"""
    version: str
    created_at: str
    checksum: str
    size_bytes: int
    metrics: Dict[str, float]
    min_app_version: Optional[str] = None
    changelog: Optional[str] = None
    download_url: Optional[str] = None


@dataclass
class UpdateConfig:
    """Configuration for model updates"""
    # Update source
    source: UpdateSource = UpdateSource.HTTP
    source_url: str = ""  # URL or path to check for updates

    # Schedule
    check_interval_hours: int = 24  # How often to check for updates
    enabled: bool = True

    # Download settings
    download_timeout_seconds: int = 300
    max_retries: int = 3
    retry_delay_seconds: int = 60

    # Validation
    validate_after_download: bool = True
    rollback_on_failure: bool = True

    # Storage
    model_dir: str = ""
    backup_dir: str = ""
    max_backups: int = 3

    # Notifications
    notify_on_update: bool = True
    webhook_url: Optional[str] = None


class ModelUpdateService:
    """
    Background service for automatic model updates

    Usage:
        updater = ModelUpdateService(config)
        await updater.start()  # Start background scheduler

        # Or manually trigger update
        result = await updater.check_and_update()
    """

    def __init__(self, config: UpdateConfig):
        self.config = config
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._current_version: Optional[ModelVersion] = None
        self._last_check: Optional[datetime] = None
        self._update_callbacks: list[Callable] = []

        # Setup directories
        if not config.model_dir:
            config.model_dir = str(Path(__file__).parent / 'models')
        if not config.backup_dir:
            config.backup_dir = str(Path(config.model_dir) / 'backups')

        Path(config.model_dir).mkdir(parents=True, exist_ok=True)
        Path(config.backup_dir).mkdir(parents=True, exist_ok=True)

        # Load current version info
        self._load_current_version()

    def _load_current_version(self):
        """Load current model version from metadata"""
        version_file = Path(self.config.model_dir) / 'version.json'
        if version_file.exists():
            try:
                with open(version_file) as f:
                    data = json.load(f)
                    self._current_version = ModelVersion(**data)
                    logger.info(f"Current model version: {self._current_version.version}")
            except Exception as e:
                logger.warning(f"Failed to load version info: {e}")

    def _save_current_version(self, version: ModelVersion):
        """Save current model version metadata"""
        version_file = Path(self.config.model_dir) / 'version.json'
        with open(version_file, 'w') as f:
            json.dump(asdict(version), f, indent=2)
        self._current_version = version

    async def start(self):
        """Start the background update scheduler"""
        if self._running:
            logger.warning("Update service already running")
            return

        if not self.config.enabled:
            logger.info("Model update service is disabled")
            return

        self._running = True
        self._task = asyncio.create_task(self._scheduler_loop())
        logger.info(
            f"Model update service started. "
            f"Checking every {self.config.check_interval_hours} hours"
        )

    async def stop(self):
        """Stop the background update scheduler"""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Model update service stopped")

    async def _scheduler_loop(self):
        """Background scheduler loop"""
        while self._running:
            try:
                # Check for updates
                await self.check_and_update()

                # Wait for next check interval
                await asyncio.sleep(self.config.check_interval_hours * 3600)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in update scheduler: {e}")
                # Wait before retrying
                await asyncio.sleep(self.config.retry_delay_seconds)

    async def check_and_update(self) -> Dict[str, Any]:
        """
        Check for updates and download if available

        Returns:
            Dict with update status and details
        """
        self._last_check = datetime.now()

        result = {
            'checked_at': self._last_check.isoformat(),
            'current_version': self._current_version.version if self._current_version else None,
            'update_available': False,
            'updated': False,
            'new_version': None,
            'error': None
        }

        try:
            # Step 1: Check for available updates
            logger.info("Checking for model updates...")
            available = await self._check_for_updates()

            if not available:
                logger.info("No updates available")
                return result

            result['update_available'] = True
            result['new_version'] = available.version

            # Step 2: Compare versions
            if self._current_version and available.version == self._current_version.version:
                logger.info(f"Already on latest version: {available.version}")
                return result

            logger.info(f"New version available: {available.version}")

            # Step 3: Download and install update
            success = await self._download_and_install(available)

            if success:
                result['updated'] = True
                logger.info(f"Successfully updated to version {available.version}")

                # Notify callbacks
                await self._notify_update(available)
            else:
                result['error'] = "Update installation failed"

        except Exception as e:
            logger.error(f"Update check failed: {e}")
            result['error'] = str(e)

        return result

    async def _check_for_updates(self) -> Optional[ModelVersion]:
        """Check update source for available versions"""

        if self.config.source == UpdateSource.HTTP:
            return await self._check_http_updates()
        elif self.config.source == UpdateSource.LOCAL:
            return await self._check_local_updates()
        elif self.config.source == UpdateSource.S3:
            return await self._check_s3_updates()
        else:
            logger.warning(f"Unsupported update source: {self.config.source}")
            return None

    async def _check_http_updates(self) -> Optional[ModelVersion]:
        """Check HTTP endpoint for updates"""
        if not self.config.source_url:
            logger.warning("No source URL configured for HTTP updates")
            return None

        try:
            # Expect a manifest.json at the source URL
            manifest_url = f"{self.config.source_url.rstrip('/')}/manifest.json"

            async with aiohttp.ClientSession() as session:
                async with session.get(manifest_url, timeout=30) as response:
                    if response.status != 200:
                        logger.warning(f"Failed to fetch manifest: HTTP {response.status}")
                        return None

                    manifest = await response.json()

            # Get latest version from manifest
            latest = manifest.get('latest')
            if not latest:
                return None

            return ModelVersion(
                version=latest['version'],
                created_at=latest.get('created_at', ''),
                checksum=latest.get('checksum', ''),
                size_bytes=latest.get('size_bytes', 0),
                metrics=latest.get('metrics', {}),
                changelog=latest.get('changelog'),
                download_url=latest.get('download_url',
                    f"{self.config.source_url.rstrip('/')}/models/{latest['version']}/model.pt"
                )
            )

        except Exception as e:
            logger.error(f"HTTP update check failed: {e}")
            return None

    async def _check_local_updates(self) -> Optional[ModelVersion]:
        """Check local directory for updates (for testing)"""
        if not self.config.source_url:
            return None

        manifest_path = Path(self.config.source_url) / 'manifest.json'
        if not manifest_path.exists():
            return None

        try:
            with open(manifest_path) as f:
                manifest = json.load(f)

            latest = manifest.get('latest')
            if not latest:
                return None

            return ModelVersion(
                version=latest['version'],
                created_at=latest.get('created_at', ''),
                checksum=latest.get('checksum', ''),
                size_bytes=latest.get('size_bytes', 0),
                metrics=latest.get('metrics', {}),
                download_url=str(Path(self.config.source_url) / 'models' / latest['version'] / 'model.pt')
            )

        except Exception as e:
            logger.error(f"Local update check failed: {e}")
            return None

    async def _check_s3_updates(self) -> Optional[ModelVersion]:
        """Check S3 bucket for updates"""
        # Placeholder for S3 implementation
        # Would use boto3/aioboto3 to check S3 bucket
        logger.warning("S3 update source not yet implemented")
        return None

    async def _download_and_install(self, version: ModelVersion) -> bool:
        """Download and install a model version"""
        try:
            # Step 1: Create backup of current model
            if self.config.rollback_on_failure:
                await self._create_backup()

            # Step 2: Download to temp location
            temp_dir = tempfile.mkdtemp()
            temp_model_path = Path(temp_dir) / 'model.pt'

            try:
                await self._download_model(version, temp_model_path)

                # Step 3: Verify checksum
                if version.checksum:
                    actual_checksum = self._compute_checksum(temp_model_path)
                    if actual_checksum != version.checksum:
                        raise ValueError(
                            f"Checksum mismatch: expected {version.checksum}, got {actual_checksum}"
                        )

                # Step 4: Validate model (optional)
                if self.config.validate_after_download:
                    valid = await self._validate_model(temp_model_path)
                    if not valid:
                        raise ValueError("Model validation failed")

                # Step 5: Install model
                target_path = Path(self.config.model_dir) / 'model.pt'
                shutil.move(str(temp_model_path), str(target_path))

                # Step 6: Save version info
                self._save_current_version(version)

                return True

            finally:
                # Cleanup temp directory
                shutil.rmtree(temp_dir, ignore_errors=True)

        except Exception as e:
            logger.error(f"Model installation failed: {e}")

            # Rollback if enabled
            if self.config.rollback_on_failure:
                await self._rollback()

            return False

    async def _download_model(self, version: ModelVersion, target_path: Path):
        """Download model file"""
        if not version.download_url:
            raise ValueError("No download URL specified")

        logger.info(f"Downloading model from {version.download_url}")

        if version.download_url.startswith(('http://', 'https://')):
            # HTTP download
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    version.download_url,
                    timeout=aiohttp.ClientTimeout(total=self.config.download_timeout_seconds)
                ) as response:
                    if response.status != 200:
                        raise ValueError(f"Download failed: HTTP {response.status}")

                    with open(target_path, 'wb') as f:
                        async for chunk in response.content.iter_chunked(8192):
                            f.write(chunk)

        else:
            # Local file copy
            shutil.copy(version.download_url, target_path)

        logger.info(f"Downloaded model to {target_path}")

    def _compute_checksum(self, file_path: Path) -> str:
        """Compute SHA256 checksum of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    async def _validate_model(self, model_path: Path) -> bool:
        """Validate downloaded model"""
        try:
            import torch
            from .gnn_model import CodeVulnerabilityGNN

            # Try to load the model
            state_dict = torch.load(model_path, map_location='cpu')

            # Create model instance and load weights
            model = CodeVulnerabilityGNN()
            model.load_state_dict(state_dict)

            # Quick inference test
            model.eval()
            with torch.no_grad():
                dummy_x = torch.randn(5, 10)
                dummy_edge = torch.randint(0, 5, (2, 10))
                dummy_batch = torch.zeros(5, dtype=torch.long)
                output = model(dummy_x, dummy_edge, dummy_batch)

            logger.info("Model validation passed")
            return True

        except Exception as e:
            logger.error(f"Model validation failed: {e}")
            return False

    async def _create_backup(self):
        """Create backup of current model"""
        current_model = Path(self.config.model_dir) / 'model.pt'
        if not current_model.exists():
            return

        # Create timestamped backup
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        version = self._current_version.version if self._current_version else 'unknown'
        backup_name = f"model_{version}_{timestamp}.pt"
        backup_path = Path(self.config.backup_dir) / backup_name

        shutil.copy(current_model, backup_path)
        logger.info(f"Created backup: {backup_path}")

        # Cleanup old backups
        await self._cleanup_old_backups()

    async def _cleanup_old_backups(self):
        """Remove old backups, keeping only max_backups most recent"""
        backup_dir = Path(self.config.backup_dir)
        backups = sorted(backup_dir.glob('model_*.pt'), key=lambda p: p.stat().st_mtime)

        while len(backups) > self.config.max_backups:
            oldest = backups.pop(0)
            oldest.unlink()
            logger.info(f"Removed old backup: {oldest}")

    async def _rollback(self):
        """Rollback to previous model version"""
        backup_dir = Path(self.config.backup_dir)
        backups = sorted(backup_dir.glob('model_*.pt'), key=lambda p: p.stat().st_mtime)

        if not backups:
            logger.warning("No backups available for rollback")
            return

        latest_backup = backups[-1]
        target_path = Path(self.config.model_dir) / 'model.pt'

        shutil.copy(latest_backup, target_path)
        logger.info(f"Rolled back to: {latest_backup}")

    def on_update(self, callback: Callable):
        """Register callback for update notifications"""
        self._update_callbacks.append(callback)

    async def _notify_update(self, version: ModelVersion):
        """Notify about successful update"""
        # Call registered callbacks
        for callback in self._update_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(version)
                else:
                    callback(version)
            except Exception as e:
                logger.warning(f"Update callback failed: {e}")

        # Send webhook notification if configured
        if self.config.notify_on_update and self.config.webhook_url:
            await self._send_webhook_notification(version)

    async def _send_webhook_notification(self, version: ModelVersion):
        """Send webhook notification about update"""
        try:
            payload = {
                'event': 'model_updated',
                'version': version.version,
                'timestamp': datetime.now().isoformat(),
                'metrics': version.metrics,
                'changelog': version.changelog
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.webhook_url,
                    json=payload,
                    timeout=10
                ) as response:
                    if response.status != 200:
                        logger.warning(f"Webhook notification failed: HTTP {response.status}")

        except Exception as e:
            logger.warning(f"Webhook notification failed: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get update service status"""
        return {
            'enabled': self.config.enabled,
            'running': self._running,
            'current_version': self._current_version.version if self._current_version else None,
            'last_check': self._last_check.isoformat() if self._last_check else None,
            'check_interval_hours': self.config.check_interval_hours,
            'source': self.config.source.value,
            'source_url': self.config.source_url
        }

    async def force_update(self) -> Dict[str, Any]:
        """Force an immediate update check"""
        return await self.check_and_update()


# Singleton instance
_update_service: Optional[ModelUpdateService] = None


async def get_update_service(config: Optional[UpdateConfig] = None) -> ModelUpdateService:
    """Get or create the update service singleton"""
    global _update_service

    if _update_service is None:
        if config is None:
            config = UpdateConfig()
        _update_service = ModelUpdateService(config)

    return _update_service
