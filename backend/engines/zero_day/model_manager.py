"""
Smart Model Manager for Zero-Day Detection
Handles model loading, updates, and optional incremental learning

Design Philosophy:
- Load pre-trained model on startup (fast)
- Collect feedback during operation
- Optionally fine-tune in background when sufficient feedback accumulated
- Never block the main application
"""

import os
import json
import logging
import asyncio
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from collections import deque
import hashlib

logger = logging.getLogger(__name__)

# Default model directory
DEFAULT_MODEL_DIR = Path(__file__).parent / 'models'
DEFAULT_FEEDBACK_DIR = Path(__file__).parent / 'feedback'


@dataclass
class FeedbackSample:
    """User feedback on a detection"""
    code_hash: str
    file_path: str
    detected_vulns: List[str]
    confirmed_vulns: List[str]  # User-confirmed vulnerabilities
    false_positives: List[str]  # User-marked false positives
    missed_vulns: List[str]  # User-reported missed vulnerabilities
    timestamp: str


@dataclass
class ModelManagerConfig:
    """Configuration for model manager"""
    # Model loading
    model_dir: str = str(DEFAULT_MODEL_DIR)
    auto_download: bool = True  # Download model if not present

    # Feedback collection
    collect_feedback: bool = True
    feedback_dir: str = str(DEFAULT_FEEDBACK_DIR)
    min_feedback_for_finetune: int = 100  # Minimum samples before fine-tuning

    # Background fine-tuning (DISABLED by default - requires explicit opt-in)
    enable_background_finetune: bool = False
    finetune_interval_days: int = 30  # How often to check for fine-tuning
    finetune_at_startup: bool = False  # Never fine-tune at startup
    max_finetune_time_minutes: int = 30  # Limit fine-tuning time

    # Model updates
    check_for_updates: bool = True
    update_url: Optional[str] = None  # URL to check for model updates


class ModelManager:
    """
    Manages GNN model lifecycle

    Responsibilities:
    - Load pre-trained model on startup
    - Collect user feedback on detections
    - Optionally fine-tune in background (when enabled and sufficient data)
    - Check for and apply model updates
    """

    def __init__(self, config: Optional[ModelManagerConfig] = None):
        self.config = config or ModelManagerConfig()
        self._model = None
        self._inference_engine = None
        self._feedback_buffer: deque = deque(maxlen=1000)
        self._lock = threading.Lock()
        self._finetune_task: Optional[asyncio.Task] = None
        self._last_finetune: Optional[datetime] = None

        # Ensure directories exist
        Path(self.config.model_dir).mkdir(parents=True, exist_ok=True)
        Path(self.config.feedback_dir).mkdir(parents=True, exist_ok=True)

        # Load metadata
        self._metadata = self._load_metadata()

    def _load_metadata(self) -> Dict:
        """Load model manager metadata"""
        metadata_path = Path(self.config.model_dir) / 'manager_metadata.json'
        if metadata_path.exists():
            with open(metadata_path) as f:
                return json.load(f)
        return {
            'last_finetune': None,
            'model_version': None,
            'feedback_count': 0
        }

    def _save_metadata(self):
        """Save model manager metadata"""
        metadata_path = Path(self.config.model_dir) / 'manager_metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(self._metadata, f, indent=2)

    async def initialize(self) -> bool:
        """
        Initialize model manager - call this on application startup

        Returns:
            True if model loaded successfully
        """
        logger.info("Initializing Model Manager...")

        # Step 1: Try to load existing model
        model_loaded = await self._load_model()

        if not model_loaded and self.config.auto_download:
            # Step 2: Try to download pre-trained model
            logger.info("No local model found. Attempting to download...")
            model_loaded = await self._download_pretrained_model()

        if not model_loaded:
            # Step 3: Use pattern-based detection only (fallback)
            logger.warning(
                "No GNN model available. Using pattern-based detection only. "
                "To enable GNN detection, train a model using: "
                "python -m engines.zero_day.train_model train --data-dir <path>"
            )
            return False

        # Step 4: Load accumulated feedback
        self._load_feedback()

        # Step 5: Check if fine-tuning needed (background, non-blocking)
        if self.config.enable_background_finetune:
            asyncio.create_task(self._check_finetune_needed())

        logger.info(f"Model Manager initialized. Model version: {self._metadata.get('model_version', 'unknown')}")
        return True

    async def _load_model(self) -> bool:
        """Load model from disk"""
        model_path = Path(self.config.model_dir) / 'model.pt'

        if not model_path.exists():
            return False

        try:
            from .serving.inference import GNNInferenceEngine, InferenceConfig

            config = InferenceConfig(
                model_path=str(model_path),
                config_path=str(Path(self.config.model_dir) / 'config.json')
            )

            self._inference_engine = GNNInferenceEngine(config)
            logger.info(f"Loaded model from {model_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False

    async def _download_pretrained_model(self) -> bool:
        """
        Download pre-trained model

        In production, this would download from a model registry.
        For now, we'll create a placeholder that uses the untrained model.
        """
        if not self.config.update_url:
            logger.info("No model update URL configured. Skipping download.")
            return False

        try:
            # In production: download from self.config.update_url
            # For now, just log that we would download
            logger.info(f"Would download model from: {self.config.update_url}")

            # Placeholder: could use httpx/aiohttp to download
            # async with httpx.AsyncClient() as client:
            #     response = await client.get(self.config.update_url)
            #     ...

            return False

        except Exception as e:
            logger.error(f"Failed to download model: {e}")
            return False

    def _load_feedback(self):
        """Load accumulated feedback from disk"""
        feedback_file = Path(self.config.feedback_dir) / 'feedback.jsonl'

        if not feedback_file.exists():
            return

        try:
            with open(feedback_file) as f:
                for line in f:
                    if line.strip():
                        sample = json.loads(line)
                        self._feedback_buffer.append(FeedbackSample(**sample))

            logger.info(f"Loaded {len(self._feedback_buffer)} feedback samples")

        except Exception as e:
            logger.warning(f"Failed to load feedback: {e}")

    async def predict(
        self,
        code: str,
        file_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Predict vulnerabilities in code

        Args:
            code: Source code to analyze
            file_path: Optional file path for context

        Returns:
            Prediction result with vulnerabilities and confidence
        """
        if self._inference_engine is None:
            return {
                'vulnerabilities': [],
                'model_available': False,
                'message': 'GNN model not loaded. Using pattern-based detection only.'
            }

        result = self._inference_engine.predict(code, file_path)

        return {
            'vulnerabilities': result.vulnerabilities,
            'confidence_scores': result.confidence_scores,
            'inference_time_ms': result.inference_time_ms,
            'model_version': result.model_version,
            'model_available': True
        }

    async def submit_feedback(
        self,
        code: str,
        file_path: str,
        detected_vulns: List[str],
        confirmed_vulns: List[str],
        false_positives: List[str],
        missed_vulns: List[str]
    ):
        """
        Submit user feedback on detection results

        This feedback is used for:
        1. Improving future model versions
        2. Optional background fine-tuning (if enabled)

        Args:
            code: The analyzed code
            file_path: File path
            detected_vulns: What the model detected
            confirmed_vulns: User-confirmed true positives
            false_positives: User-marked false positives
            missed_vulns: Vulnerabilities the model missed
        """
        if not self.config.collect_feedback:
            return

        # Hash the code for privacy (don't store actual code)
        code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]

        feedback = FeedbackSample(
            code_hash=code_hash,
            file_path=file_path,
            detected_vulns=detected_vulns,
            confirmed_vulns=confirmed_vulns,
            false_positives=false_positives,
            missed_vulns=missed_vulns,
            timestamp=datetime.now().isoformat()
        )

        # Add to buffer
        with self._lock:
            self._feedback_buffer.append(feedback)
            self._metadata['feedback_count'] = len(self._feedback_buffer)

        # Persist to disk
        await self._persist_feedback(feedback)

        logger.debug(f"Recorded feedback for {file_path}")

        # Check if we should trigger fine-tuning
        if (self.config.enable_background_finetune and
            len(self._feedback_buffer) >= self.config.min_feedback_for_finetune):
            asyncio.create_task(self._check_finetune_needed())

    async def _persist_feedback(self, feedback: FeedbackSample):
        """Persist feedback to disk"""
        feedback_file = Path(self.config.feedback_dir) / 'feedback.jsonl'

        try:
            with open(feedback_file, 'a') as f:
                f.write(json.dumps(asdict(feedback)) + '\n')
        except Exception as e:
            logger.warning(f"Failed to persist feedback: {e}")

    async def _check_finetune_needed(self):
        """Check if fine-tuning should be triggered"""
        if not self.config.enable_background_finetune:
            return

        # Check if already fine-tuning
        if self._finetune_task and not self._finetune_task.done():
            return

        # Check minimum feedback threshold
        if len(self._feedback_buffer) < self.config.min_feedback_for_finetune:
            return

        # Check time since last fine-tune
        if self._last_finetune:
            days_since = (datetime.now() - self._last_finetune).days
            if days_since < self.config.finetune_interval_days:
                return

        # Trigger background fine-tuning
        logger.info("Triggering background fine-tuning...")
        self._finetune_task = asyncio.create_task(self._background_finetune())

    async def _background_finetune(self):
        """
        Fine-tune model in background

        IMPORTANT: This runs in a separate thread to not block the main app
        """
        try:
            logger.info("Starting background fine-tuning...")

            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._finetune_sync)

            self._last_finetune = datetime.now()
            self._metadata['last_finetune'] = self._last_finetune.isoformat()
            self._save_metadata()

            # Reload the model
            await self._load_model()

            logger.info("Background fine-tuning complete!")

        except Exception as e:
            logger.error(f"Background fine-tuning failed: {e}")

    def _finetune_sync(self):
        """Synchronous fine-tuning (runs in thread pool)"""
        # This is a placeholder for actual fine-tuning logic
        # In production, this would:
        # 1. Convert feedback to training samples
        # 2. Load current model
        # 3. Fine-tune on feedback data
        # 4. Validate improvement
        # 5. Save new model

        logger.info("Fine-tuning would run here with accumulated feedback")

        # For now, just log the feedback statistics
        if self._feedback_buffer:
            total_fp = sum(len(f.false_positives) for f in self._feedback_buffer)
            total_fn = sum(len(f.missed_vulns) for f in self._feedback_buffer)
            total_tp = sum(len(f.confirmed_vulns) for f in self._feedback_buffer)

            logger.info(f"Feedback stats - TP: {total_tp}, FP: {total_fp}, FN: {total_fn}")

    def get_status(self) -> Dict[str, Any]:
        """Get model manager status"""
        return {
            'model_loaded': self._inference_engine is not None,
            'model_version': self._metadata.get('model_version'),
            'feedback_count': len(self._feedback_buffer),
            'last_finetune': self._metadata.get('last_finetune'),
            'finetune_enabled': self.config.enable_background_finetune,
            'min_feedback_for_finetune': self.config.min_feedback_for_finetune,
            'finetune_in_progress': (
                self._finetune_task is not None and
                not self._finetune_task.done()
            )
        }


# Singleton instance for application-wide use
_model_manager: Optional[ModelManager] = None


async def get_model_manager(config: Optional[ModelManagerConfig] = None) -> ModelManager:
    """
    Get or create the model manager singleton

    Usage in FastAPI:
        @app.on_event("startup")
        async def startup():
            manager = await get_model_manager()
            await manager.initialize()
    """
    global _model_manager

    if _model_manager is None:
        _model_manager = ModelManager(config)

    return _model_manager
