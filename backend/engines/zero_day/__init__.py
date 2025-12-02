"""
Zero-Day Detection Engine
ML-based anomaly detection and LLM-driven exploit generation

Components:
- MLAnomalyDetector: Hybrid pattern + GNN-based vulnerability detection
- CodeGraphExtractor: AST/CFG/DFG extraction for code property graphs
- CodeVulnerabilityGNN: Graph Neural Network for vulnerability classification
- VulnerabilityDetector: High-level detection interface

Training & Serving:
- training/: GNN training pipeline with CodeBERT integration
- serving/: Production model serving with versioning
- train_model.py: CLI for training and deployment
"""

from .ml_detector import MLAnomalyDetector, CodeAnomaly
from .exploit_generator import ExploitGenerator, ExploitChain
from .code_graph_extractor import CodeGraphExtractor
from .gnn_model import CodeVulnerabilityGNN, VulnerabilityDetector

__all__ = [
    # Detection
    "MLAnomalyDetector",
    "CodeAnomaly",
    "ExploitGenerator",
    "ExploitChain",
    # Graph extraction
    "CodeGraphExtractor",
    # GNN model
    "CodeVulnerabilityGNN",
    "VulnerabilityDetector",
]
