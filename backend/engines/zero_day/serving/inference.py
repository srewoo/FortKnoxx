"""
High-Performance Inference Engine for GNN Models
Optimized for production vulnerability detection
"""

import os
import json
import time
import logging
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import threading

import torch
import torch.nn as nn
import numpy as np

logger = logging.getLogger(__name__)

# Check for optimizations
try:
    import torch.jit
    JIT_AVAILABLE = True
except ImportError:
    JIT_AVAILABLE = False

try:
    from torch_geometric.data import Data, Batch
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    TORCH_GEOMETRIC_AVAILABLE = False


@dataclass
class InferenceConfig:
    """Configuration for inference engine"""
    model_path: str
    config_path: Optional[str] = None
    device: str = "auto"
    use_jit: bool = True
    batch_size: int = 32
    num_workers: int = 4
    threshold: float = 0.5
    cache_embeddings: bool = True
    max_cache_size: int = 1000


@dataclass
class InferenceResult:
    """Result from inference"""
    vulnerabilities: List[Dict[str, Any]]
    confidence_scores: Dict[str, float]
    inference_time_ms: float
    model_version: str
    file_path: Optional[str] = None


class GNNInferenceEngine:
    """
    Production-ready inference engine for GNN vulnerability detection

    Features:
    - Efficient batched inference
    - Optional JIT compilation for speed
    - Embedding caching
    - Async interface for non-blocking inference
    - Thread-safe for concurrent requests
    """

    def __init__(self, config: InferenceConfig):
        self.config = config
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=config.num_workers)

        # Set device
        if config.device == "auto":
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(config.device)

        logger.info(f"Initializing inference engine on {self.device}")

        # Load model
        self.model = self._load_model()
        self.model_version = self._get_model_version()

        # Initialize CodeBERT if available
        self._codebert = None
        self._graph_extractor = None

        # Embedding cache
        self._embedding_cache: Dict[str, np.ndarray] = {}
        self._cache_lock = threading.Lock()

        # Vulnerability types mapping
        self.vulnerability_types = [
            "sql_injection", "command_injection", "path_traversal",
            "xss", "unsafe_deserialization", "weak_crypto",
            "hardcoded_secrets", "insecure_random", "buffer_overflow",
            "use_after_free", "null_pointer_dereference", "race_condition",
            "resource_exhaustion", "memory_leak", "sensitive_data_exposure",
            "xxe", "ssrf", "ldap_injection", "xpath_injection",
            "code_injection", "authentication_bypass", "authorization_bypass",
            "session_fixation", "csrf", "open_redirect"
        ]

        logger.info(f"Inference engine ready. Model version: {self.model_version}")

    def _load_model(self) -> nn.Module:
        """Load and prepare model for inference"""
        from ..gnn_model import CodeVulnerabilityGNN

        # Load config if available
        model_config = self._load_config()

        # Create model
        model = CodeVulnerabilityGNN(
            num_node_features=model_config.get('num_node_features', 10),
            hidden_dim=model_config.get('hidden_dim', 128),
            num_classes=model_config.get('num_classes', 25),
            num_layers=model_config.get('num_layers', 3),
            dropout=0.0  # No dropout for inference
        )

        # Load weights
        model_path = Path(self.config.model_path)

        if model_path.exists():
            state_dict = torch.load(model_path, map_location=self.device)
            model.load_state_dict(state_dict)
            logger.info(f"Loaded model from {model_path}")
        else:
            logger.warning(f"Model not found at {model_path}. Using untrained model.")

        model.to(self.device)
        model.eval()

        # Optional JIT compilation for faster inference
        if self.config.use_jit and JIT_AVAILABLE:
            try:
                # Create dummy input for tracing
                dummy_x = torch.randn(10, model_config.get('num_node_features', 10)).to(self.device)
                dummy_edge = torch.randint(0, 10, (2, 20)).to(self.device)
                dummy_batch = torch.zeros(10, dtype=torch.long).to(self.device)

                model = torch.jit.trace(model, (dummy_x, dummy_edge, dummy_batch))
                logger.info("Model JIT compiled for faster inference")
            except Exception as e:
                logger.warning(f"JIT compilation failed: {e}")

        return model

    def _load_config(self) -> Dict:
        """Load model configuration"""
        if self.config.config_path:
            config_path = Path(self.config.config_path)
        else:
            # Try to find config next to model
            model_dir = Path(self.config.model_path).parent
            config_path = model_dir / 'config.json'

        if config_path.exists():
            with open(config_path) as f:
                return json.load(f)

        return {}

    def _get_model_version(self) -> str:
        """Get model version from metadata"""
        model_dir = Path(self.config.model_path).parent
        metadata_path = model_dir / 'metadata.json'

        if metadata_path.exists():
            with open(metadata_path) as f:
                metadata = json.load(f)
                return metadata.get('version', metadata.get('created_at', 'unknown'))

        return 'unknown'

    @property
    def graph_extractor(self):
        """Lazy load graph extractor"""
        if self._graph_extractor is None:
            from ..code_graph_extractor import CodeGraphExtractor
            self._graph_extractor = CodeGraphExtractor()
        return self._graph_extractor

    @property
    def codebert(self):
        """Lazy load CodeBERT embedder"""
        if self._codebert is None:
            try:
                from ..training.codebert_embeddings import CodeBERTEmbedder
                self._codebert = CodeBERTEmbedder(device=str(self.device))
            except Exception as e:
                logger.warning(f"CodeBERT not available: {e}")
        return self._codebert

    def predict(
        self,
        code: str,
        file_path: Optional[str] = None,
        threshold: Optional[float] = None
    ) -> InferenceResult:
        """
        Predict vulnerabilities in code

        Args:
            code: Source code to analyze
            file_path: Optional file path for context
            threshold: Confidence threshold (default from config)

        Returns:
            InferenceResult with detected vulnerabilities
        """
        start_time = time.time()
        threshold = threshold or self.config.threshold

        try:
            # Extract graph features
            graph_features = self._extract_features(code, file_path)

            if not graph_features['node_features']:
                return InferenceResult(
                    vulnerabilities=[],
                    confidence_scores={},
                    inference_time_ms=0,
                    model_version=self.model_version,
                    file_path=file_path
                )

            # Prepare PyG data
            data = self._prepare_data(graph_features)

            # Run inference
            with torch.no_grad():
                logits = self.model(data.x, data.edge_index, data.batch)
                probabilities = torch.sigmoid(logits).cpu().numpy().squeeze()

            # Parse results
            vulnerabilities = []
            confidence_scores = {}

            for i, prob in enumerate(probabilities):
                vuln_type = self.vulnerability_types[i]
                confidence_scores[vuln_type] = float(prob)

                if prob >= threshold:
                    vulnerabilities.append({
                        'type': vuln_type,
                        'confidence': float(prob),
                        'severity': self._get_severity(vuln_type),
                        'description': self._get_description(vuln_type),
                        'remediation': self._get_remediation(vuln_type)
                    })

            # Sort by confidence
            vulnerabilities.sort(key=lambda x: x['confidence'], reverse=True)

            inference_time = (time.time() - start_time) * 1000

            return InferenceResult(
                vulnerabilities=vulnerabilities,
                confidence_scores=confidence_scores,
                inference_time_ms=inference_time,
                model_version=self.model_version,
                file_path=file_path
            )

        except Exception as e:
            logger.error(f"Inference failed: {e}")
            return InferenceResult(
                vulnerabilities=[],
                confidence_scores={},
                inference_time_ms=0,
                model_version=self.model_version,
                file_path=file_path
            )

    async def predict_async(
        self,
        code: str,
        file_path: Optional[str] = None,
        threshold: Optional[float] = None
    ) -> InferenceResult:
        """Async version of predict for non-blocking inference"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self.predict(code, file_path, threshold)
        )

    def predict_batch(
        self,
        code_samples: List[Tuple[str, Optional[str]]],
        threshold: Optional[float] = None
    ) -> List[InferenceResult]:
        """
        Batch prediction for multiple code samples

        Args:
            code_samples: List of (code, file_path) tuples
            threshold: Confidence threshold

        Returns:
            List of InferenceResults
        """
        start_time = time.time()
        threshold = threshold or self.config.threshold

        # Extract features for all samples
        all_data = []
        valid_indices = []

        for i, (code, file_path) in enumerate(code_samples):
            try:
                features = self._extract_features(code, file_path)
                if features['node_features']:
                    data = self._prepare_data(features)
                    data.sample_idx = i
                    data.file_path = file_path
                    all_data.append(data)
                    valid_indices.append(i)
            except Exception as e:
                logger.warning(f"Failed to process sample {i}: {e}")

        if not all_data:
            return [
                InferenceResult(
                    vulnerabilities=[],
                    confidence_scores={},
                    inference_time_ms=0,
                    model_version=self.model_version,
                    file_path=fp
                )
                for _, fp in code_samples
            ]

        # Batch inference
        batch = Batch.from_data_list(all_data)
        batch = batch.to(self.device)

        with torch.no_grad():
            logits = self.model(batch.x, batch.edge_index, batch.batch)
            probabilities = torch.sigmoid(logits).cpu().numpy()

        # Parse results
        results = [None] * len(code_samples)
        inference_time = (time.time() - start_time) * 1000 / len(code_samples)

        for batch_idx, sample_idx in enumerate(valid_indices):
            probs = probabilities[batch_idx]

            vulnerabilities = []
            confidence_scores = {}

            for i, prob in enumerate(probs):
                vuln_type = self.vulnerability_types[i]
                confidence_scores[vuln_type] = float(prob)

                if prob >= threshold:
                    vulnerabilities.append({
                        'type': vuln_type,
                        'confidence': float(prob),
                        'severity': self._get_severity(vuln_type),
                        'description': self._get_description(vuln_type),
                        'remediation': self._get_remediation(vuln_type)
                    })

            vulnerabilities.sort(key=lambda x: x['confidence'], reverse=True)

            results[sample_idx] = InferenceResult(
                vulnerabilities=vulnerabilities,
                confidence_scores=confidence_scores,
                inference_time_ms=inference_time,
                model_version=self.model_version,
                file_path=code_samples[sample_idx][1]
            )

        # Fill in any missing results
        for i in range(len(results)):
            if results[i] is None:
                results[i] = InferenceResult(
                    vulnerabilities=[],
                    confidence_scores={},
                    inference_time_ms=0,
                    model_version=self.model_version,
                    file_path=code_samples[i][1]
                )

        return results

    def _extract_features(
        self,
        code: str,
        file_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Extract graph features from code"""
        # Check cache
        cache_key = hash(code)
        if self.config.cache_embeddings:
            with self._cache_lock:
                if cache_key in self._embedding_cache:
                    return self._embedding_cache[cache_key]

        # Extract CPG
        cpg = self.graph_extractor.create_code_property_graph(code, file_path or '')
        features = self.graph_extractor.extract_features(cpg)

        # Enhance with CodeBERT if available
        if self.codebert and features['node_features']:
            try:
                codebert_features = self.codebert.get_node_embeddings(
                    code,
                    len(features['node_features'])
                )
                features['node_features'] = [
                    nf + cbf for nf, cbf in zip(
                        features['node_features'],
                        codebert_features
                    )
                ]
            except Exception as e:
                logger.debug(f"CodeBERT enhancement failed: {e}")

        # Cache result
        if self.config.cache_embeddings:
            with self._cache_lock:
                if len(self._embedding_cache) >= self.config.max_cache_size:
                    # Simple eviction - clear half
                    keys = list(self._embedding_cache.keys())
                    for k in keys[:len(keys) // 2]:
                        del self._embedding_cache[k]
                self._embedding_cache[cache_key] = features

        return features

    def _prepare_data(self, features: Dict) -> Data:
        """Prepare PyG Data object"""
        x = torch.FloatTensor(features['node_features']).to(self.device)

        if features['edge_indices']:
            edge_index = torch.LongTensor(features['edge_indices']).t().contiguous().to(self.device)
        else:
            num_nodes = len(features['node_features'])
            edge_index = torch.stack([
                torch.arange(num_nodes),
                torch.arange(num_nodes)
            ]).to(self.device)

        batch = torch.zeros(len(features['node_features']), dtype=torch.long).to(self.device)

        return Data(x=x, edge_index=edge_index, batch=batch)

    def _get_severity(self, vuln_type: str) -> str:
        """Map vulnerability type to severity"""
        critical = ['sql_injection', 'command_injection', 'unsafe_deserialization',
                   'authentication_bypass', 'authorization_bypass', 'buffer_overflow']
        high = ['xss', 'path_traversal', 'weak_crypto', 'hardcoded_secrets',
               'ssrf', 'xxe', 'code_injection']

        if vuln_type in critical:
            return 'critical'
        elif vuln_type in high:
            return 'high'
        return 'medium'

    def _get_description(self, vuln_type: str) -> str:
        """Get vulnerability description"""
        descriptions = {
            'sql_injection': 'SQL Injection allows attackers to execute arbitrary SQL commands',
            'command_injection': 'Command Injection allows execution of arbitrary system commands',
            'path_traversal': 'Path Traversal allows access to files outside intended directory',
            'xss': 'Cross-Site Scripting allows injection of malicious scripts',
            'unsafe_deserialization': 'Unsafe Deserialization can lead to remote code execution',
            'weak_crypto': 'Weak cryptographic algorithms can be broken by attackers',
            'hardcoded_secrets': 'Hardcoded secrets can be extracted from code',
            'ssrf': 'Server-Side Request Forgery allows internal network access',
            'xxe': 'XML External Entity injection can leak sensitive data',
        }
        return descriptions.get(vuln_type, f'Potential {vuln_type.replace("_", " ")} vulnerability')

    def _get_remediation(self, vuln_type: str) -> str:
        """Get remediation advice"""
        remediations = {
            'sql_injection': 'Use parameterized queries or ORM',
            'command_injection': 'Avoid shell=True, validate and sanitize inputs',
            'path_traversal': 'Validate paths and use safe path joining',
            'xss': 'Encode output and use Content Security Policy',
            'unsafe_deserialization': 'Use safe serialization formats like JSON',
            'weak_crypto': 'Use modern algorithms (AES-256, SHA-256, bcrypt)',
            'hardcoded_secrets': 'Use environment variables or secret managers',
            'ssrf': 'Validate and whitelist URLs, block internal addresses',
            'xxe': 'Disable external entity processing in XML parsers',
        }
        return remediations.get(vuln_type, 'Review and update code following security best practices')

    def clear_cache(self):
        """Clear embedding cache"""
        with self._cache_lock:
            self._embedding_cache.clear()
        logger.info("Embedding cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """Get inference engine statistics"""
        return {
            'model_version': self.model_version,
            'device': str(self.device),
            'cache_size': len(self._embedding_cache),
            'max_cache_size': self.config.max_cache_size,
            'threshold': self.config.threshold,
            'num_vulnerability_types': len(self.vulnerability_types)
        }
