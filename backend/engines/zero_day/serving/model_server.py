"""
Model Registry and Serving Infrastructure
Manages model versioning, deployment, and A/B testing
"""

import os
import json
import shutil
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import hashlib
import threading

logger = logging.getLogger(__name__)


@dataclass
class ModelMetadata:
    """Metadata for a registered model"""
    model_id: str
    version: str
    created_at: str
    metrics: Dict[str, float]
    config: Dict[str, Any]
    tags: List[str]
    description: str
    file_path: str
    checksum: str
    is_active: bool = False
    is_champion: bool = False


class ModelRegistry:
    """
    Registry for managing model versions

    Features:
    - Version tracking
    - Model comparison
    - Champion/Challenger management
    - Rollback support
    """

    def __init__(self, registry_dir: str):
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)

        self.models_dir = self.registry_dir / 'models'
        self.models_dir.mkdir(exist_ok=True)

        self.registry_file = self.registry_dir / 'registry.json'
        self._lock = threading.Lock()

        # Load existing registry
        self.registry = self._load_registry()

    def _load_registry(self) -> Dict[str, ModelMetadata]:
        """Load registry from disk"""
        if self.registry_file.exists():
            with open(self.registry_file) as f:
                data = json.load(f)
                return {
                    k: ModelMetadata(**v)
                    for k, v in data.items()
                }
        return {}

    def _save_registry(self):
        """Save registry to disk"""
        data = {k: asdict(v) for k, v in self.registry.items()}
        with open(self.registry_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _compute_checksum(self, file_path: Path) -> str:
        """Compute MD5 checksum of model file"""
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()

    def register_model(
        self,
        model_path: str,
        version: str,
        metrics: Dict[str, float],
        config: Dict[str, Any],
        tags: Optional[List[str]] = None,
        description: str = ""
    ) -> ModelMetadata:
        """
        Register a new model version

        Args:
            model_path: Path to model weights file
            version: Version string (e.g., "1.0.0")
            metrics: Evaluation metrics
            config: Model configuration
            tags: Optional tags for filtering
            description: Human-readable description

        Returns:
            ModelMetadata for registered model
        """
        with self._lock:
            # Generate unique ID
            model_id = f"gnn_vuln_{version}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Copy model to registry
            source_path = Path(model_path)
            dest_path = self.models_dir / f"{model_id}.pt"
            shutil.copy(source_path, dest_path)

            # Compute checksum
            checksum = self._compute_checksum(dest_path)

            # Create metadata
            metadata = ModelMetadata(
                model_id=model_id,
                version=version,
                created_at=datetime.now().isoformat(),
                metrics=metrics,
                config=config,
                tags=tags or [],
                description=description,
                file_path=str(dest_path),
                checksum=checksum
            )

            # Register
            self.registry[model_id] = metadata
            self._save_registry()

            logger.info(f"Registered model: {model_id}")
            return metadata

    def get_model(self, model_id: str) -> Optional[ModelMetadata]:
        """Get model metadata by ID"""
        return self.registry.get(model_id)

    def get_champion(self) -> Optional[ModelMetadata]:
        """Get the current champion model"""
        for metadata in self.registry.values():
            if metadata.is_champion:
                return metadata
        return None

    def get_active_models(self) -> List[ModelMetadata]:
        """Get all active models"""
        return [m for m in self.registry.values() if m.is_active]

    def set_champion(self, model_id: str):
        """Set a model as the champion"""
        with self._lock:
            if model_id not in self.registry:
                raise ValueError(f"Model not found: {model_id}")

            # Remove current champion
            for metadata in self.registry.values():
                metadata.is_champion = False

            # Set new champion
            self.registry[model_id].is_champion = True
            self.registry[model_id].is_active = True
            self._save_registry()

            logger.info(f"Set champion model: {model_id}")

    def activate_model(self, model_id: str):
        """Activate a model for serving"""
        with self._lock:
            if model_id not in self.registry:
                raise ValueError(f"Model not found: {model_id}")

            self.registry[model_id].is_active = True
            self._save_registry()

    def deactivate_model(self, model_id: str):
        """Deactivate a model"""
        with self._lock:
            if model_id not in self.registry:
                raise ValueError(f"Model not found: {model_id}")

            self.registry[model_id].is_active = False
            self._save_registry()

    def compare_models(
        self,
        model_id_1: str,
        model_id_2: str
    ) -> Dict[str, Any]:
        """Compare two models by their metrics"""
        m1 = self.registry.get(model_id_1)
        m2 = self.registry.get(model_id_2)

        if not m1 or not m2:
            raise ValueError("One or both models not found")

        comparison = {
            'model_1': model_id_1,
            'model_2': model_id_2,
            'metrics_comparison': {}
        }

        # Compare metrics
        all_metrics = set(m1.metrics.keys()) | set(m2.metrics.keys())
        for metric in all_metrics:
            v1 = m1.metrics.get(metric, 0)
            v2 = m2.metrics.get(metric, 0)
            comparison['metrics_comparison'][metric] = {
                'model_1': v1,
                'model_2': v2,
                'diff': v2 - v1,
                'improvement': (v2 - v1) / v1 * 100 if v1 > 0 else 0
            }

        return comparison

    def list_models(
        self,
        tags: Optional[List[str]] = None,
        version_prefix: Optional[str] = None
    ) -> List[ModelMetadata]:
        """List models with optional filtering"""
        models = list(self.registry.values())

        if tags:
            models = [m for m in models if any(t in m.tags for t in tags)]

        if version_prefix:
            models = [m for m in models if m.version.startswith(version_prefix)]

        # Sort by creation date (newest first)
        models.sort(key=lambda m: m.created_at, reverse=True)

        return models

    def delete_model(self, model_id: str, force: bool = False):
        """Delete a model from registry"""
        with self._lock:
            if model_id not in self.registry:
                raise ValueError(f"Model not found: {model_id}")

            metadata = self.registry[model_id]

            if metadata.is_champion and not force:
                raise ValueError("Cannot delete champion model. Use force=True")

            # Delete model file
            model_path = Path(metadata.file_path)
            if model_path.exists():
                model_path.unlink()

            # Remove from registry
            del self.registry[model_id]
            self._save_registry()

            logger.info(f"Deleted model: {model_id}")


class ModelServer:
    """
    Production model server with support for:
    - Multiple model versions
    - A/B testing
    - Shadow mode evaluation
    - Graceful model updates
    """

    def __init__(
        self,
        registry: ModelRegistry,
        device: str = "auto"
    ):
        self.registry = registry
        self.device = device

        self._engines: Dict[str, Any] = {}  # model_id -> InferenceEngine
        self._lock = threading.Lock()

        # Load active models
        self._load_active_models()

    def _load_active_models(self):
        """Load all active models into memory"""
        from .inference import GNNInferenceEngine, InferenceConfig

        active_models = self.registry.get_active_models()

        for metadata in active_models:
            try:
                config = InferenceConfig(
                    model_path=metadata.file_path,
                    device=self.device
                )
                engine = GNNInferenceEngine(config)
                self._engines[metadata.model_id] = engine
                logger.info(f"Loaded model: {metadata.model_id}")
            except Exception as e:
                logger.error(f"Failed to load model {metadata.model_id}: {e}")

    def predict(
        self,
        code: str,
        file_path: Optional[str] = None,
        model_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Make prediction using specified or champion model

        Args:
            code: Source code to analyze
            file_path: Optional file path
            model_id: Specific model to use (default: champion)

        Returns:
            Prediction result
        """
        # Get model
        if model_id:
            if model_id not in self._engines:
                raise ValueError(f"Model not loaded: {model_id}")
            engine = self._engines[model_id]
        else:
            # Use champion
            champion = self.registry.get_champion()
            if not champion:
                raise ValueError("No champion model set")
            if champion.model_id not in self._engines:
                raise ValueError(f"Champion model not loaded: {champion.model_id}")
            engine = self._engines[champion.model_id]

        # Run inference
        result = engine.predict(code, file_path)

        return {
            'vulnerabilities': result.vulnerabilities,
            'confidence_scores': result.confidence_scores,
            'inference_time_ms': result.inference_time_ms,
            'model_version': result.model_version
        }

    def predict_ab_test(
        self,
        code: str,
        file_path: Optional[str] = None,
        model_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Run A/B test prediction with multiple models

        Returns results from all specified models for comparison
        """
        if model_ids is None:
            # Default: champion vs all challengers
            active = self.registry.get_active_models()
            model_ids = [m.model_id for m in active]

        results = {}
        for model_id in model_ids:
            if model_id in self._engines:
                try:
                    result = self._engines[model_id].predict(code, file_path)
                    results[model_id] = {
                        'vulnerabilities': result.vulnerabilities,
                        'confidence_scores': result.confidence_scores,
                        'inference_time_ms': result.inference_time_ms
                    }
                except Exception as e:
                    logger.error(f"Model {model_id} failed: {e}")
                    results[model_id] = {'error': str(e)}

        return results

    def reload_model(self, model_id: str):
        """Reload a model (e.g., after update)"""
        from .inference import GNNInferenceEngine, InferenceConfig

        with self._lock:
            metadata = self.registry.get_model(model_id)
            if not metadata:
                raise ValueError(f"Model not found: {model_id}")

            config = InferenceConfig(
                model_path=metadata.file_path,
                device=self.device
            )

            engine = GNNInferenceEngine(config)
            self._engines[model_id] = engine

            logger.info(f"Reloaded model: {model_id}")

    def unload_model(self, model_id: str):
        """Unload a model from memory"""
        with self._lock:
            if model_id in self._engines:
                del self._engines[model_id]
                logger.info(f"Unloaded model: {model_id}")

    def get_loaded_models(self) -> List[str]:
        """Get list of loaded model IDs"""
        return list(self._engines.keys())

    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics"""
        champion = self.registry.get_champion()

        return {
            'loaded_models': len(self._engines),
            'champion_model': champion.model_id if champion else None,
            'total_registered': len(self.registry.registry),
            'models': {
                model_id: engine.get_stats()
                for model_id, engine in self._engines.items()
            }
        }


def deploy_model(
    model_path: str,
    registry_dir: str,
    version: str,
    metrics: Dict[str, float],
    config: Dict[str, Any],
    set_as_champion: bool = False,
    description: str = ""
) -> ModelMetadata:
    """
    Helper function to deploy a new model

    Args:
        model_path: Path to trained model weights
        registry_dir: Path to model registry
        version: Version string
        metrics: Evaluation metrics
        config: Model configuration
        set_as_champion: Whether to set as champion
        description: Model description

    Returns:
        ModelMetadata for deployed model
    """
    registry = ModelRegistry(registry_dir)

    # Register model
    metadata = registry.register_model(
        model_path=model_path,
        version=version,
        metrics=metrics,
        config=config,
        tags=['gnn', 'vulnerability-detection'],
        description=description
    )

    # Activate
    registry.activate_model(metadata.model_id)

    # Optionally set as champion
    if set_as_champion:
        registry.set_champion(metadata.model_id)

    logger.info(f"Deployed model {metadata.model_id} (champion={set_as_champion})")

    return metadata
