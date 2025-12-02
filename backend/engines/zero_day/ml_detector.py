"""
ML-Based Anomaly Detector
Detects unusual code patterns that may indicate zero-day vulnerabilities
Now enhanced with Graph Neural Networks for advanced detection
"""

from typing import List, Dict, Optional
from pydantic import BaseModel, Field
from pathlib import Path
import re
import ast
import logging

logger = logging.getLogger(__name__)

# Import GNN components
try:
    from .code_graph_extractor import CodeGraphExtractor
    from .gnn_model import VulnerabilityDetector
    GNN_AVAILABLE = True
    logger.info("GNN components loaded successfully")
except ImportError as e:
    logger.warning(f"GNN components not available: {str(e)}. Using pattern-based detection only.")
    GNN_AVAILABLE = False


class CodeAnomaly(BaseModel):
    """Detected code anomaly"""
    type: str  # unsafe_crypto, custom_auth, serialization, etc.
    title: str
    description: str
    severity: str
    confidence: float

    file_path: str
    line_number: int
    code_snippet: str

    anomaly_score: float  # 0-1, how unusual the pattern is
    remediation: str


class MLAnomalyDetector:
    """
    Detects code anomalies using:
    1. Pattern matching (traditional)
    2. Graph Neural Networks (advanced ML)
    """

    def __init__(self, use_gnn: bool = True, model_path: Optional[str] = None):
        self.anomalies: List[CodeAnomaly] = []
        self.use_gnn = use_gnn and GNN_AVAILABLE

        # Initialize GNN components if available
        if self.use_gnn:
            try:
                self.graph_extractor = CodeGraphExtractor()
                self.gnn_detector = VulnerabilityDetector(model_path=model_path)
                logger.info("GNN-based detection enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize GNN: {str(e)}. Falling back to pattern-based detection.")
                self.use_gnn = False

        # Patterns for different anomaly types
        self.patterns = {
            "unsafe_crypto": [
                r"md5\(",
                r"sha1\(",
                r"DES\(",
                r"ECB",
                r"random\.random\(\)",  # Not cryptographically secure
            ],
            "custom_auth": [
                r"def.*authenticate.*:\s*\n.*==",  # Custom comparison
                r"password\s*==\s*[\"']",  # Hardcoded password check
            ],
            "serialization": [
                r"pickle\.loads?\(",
                r"eval\(",
                r"exec\(",
                r"__import__\(",
            ],
            "sql_building": [
                r"\"SELECT.*\+",  # String concatenation in SQL
                r"f\".*SELECT.*\{",  # f-string SQL
            ],
            "command_execution": [
                r"os\.system\(",
                r"subprocess\.call\([^)]*shell\s*=\s*True",
            ]
        }

    async def analyze_repository(self, repo_path: str) -> List[CodeAnomaly]:
        """
        Analyze repository for code anomalies using hybrid approach:
        1. Pattern-based detection (fast, high precision)
        2. GNN-based detection (slower, better recall)
        """
        logger.info(f"Running ML anomaly detection on {repo_path}")
        logger.info(f"GNN enabled: {self.use_gnn}")

        self.anomalies = []
        repo_path_obj = Path(repo_path)

        python_files = list(repo_path_obj.rglob("*.py"))
        logger.info(f"Found {len(python_files)} Python files to analyze")

        for py_file in python_files:
            # Pattern-based detection (always run)
            await self._analyze_file_patterns(str(py_file))

            # GNN-based detection (if enabled)
            if self.use_gnn:
                await self._analyze_file_gnn(str(py_file))

        logger.info(f"Found {len(self.anomalies)} code anomalies")
        return self.anomalies

    async def _analyze_file_patterns(self, file_path: str):
        """Analyze single file for anomalies using pattern matching"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Check each pattern type
            for anomaly_type, patterns in self.patterns.items():
                for pattern in patterns:
                    for match in re.finditer(pattern, content):
                        line_number = content[:match.start()].count('\n') + 1

                        # Extract code snippet
                        lines = content.split('\n')
                        start = max(0, line_number - 2)
                        end = min(len(lines), line_number + 2)
                        snippet = '\n'.join(lines[start:end])

                        anomaly = CodeAnomaly(
                            type=anomaly_type,
                            title=f"Potential {anomaly_type.replace('_', ' ')}",
                            description=self._get_description(anomaly_type),
                            severity=self._get_severity(anomaly_type),
                            confidence=0.6,
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=snippet,
                            anomaly_score=0.7,
                            remediation=self._get_remediation(anomaly_type)
                        )

                        self.anomalies.append(anomaly)

        except Exception as e:
            logger.warning(f"Error in pattern analysis of {file_path}: {str(e)}")

    async def _analyze_file_gnn(self, file_path: str):
        """Analyze single file using Graph Neural Network"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Extract code property graph
            cpg = self.graph_extractor.create_code_property_graph(content, file_path)

            if cpg.number_of_nodes() == 0:
                logger.debug(f"Empty graph for {file_path}, skipping GNN analysis")
                return

            # Extract features for GNN
            graph_features = self.graph_extractor.extract_features(cpg)

            # Run GNN detection
            vulnerabilities = self.gnn_detector.detect(graph_features, threshold=0.5)

            # Convert to CodeAnomaly format
            for vuln in vulnerabilities:
                anomaly = CodeAnomaly(
                    type=vuln['type'],
                    title=f"GNN-detected: {vuln['type'].replace('_', ' ').title()}",
                    description=f"Machine learning model detected potential {vuln['type']} vulnerability",
                    severity=vuln['severity'],
                    confidence=vuln['confidence'],
                    file_path=file_path,
                    line_number=1,  # GNN gives file-level detection
                    code_snippet="[Full file analysis - see file]",
                    anomaly_score=vuln['confidence'],
                    remediation=self._get_remediation(vuln['type'])
                )

                self.anomalies.append(anomaly)

        except Exception as e:
            logger.warning(f"Error in GNN analysis of {file_path}: {str(e)}")

    def _get_description(self, anomaly_type: str) -> str:
        descriptions = {
            "unsafe_crypto": "Usage of weak or deprecated cryptographic functions",
            "custom_auth": "Custom authentication implementation that may have flaws",
            "serialization": "Unsafe deserialization that can lead to code execution",
            "sql_building": "SQL query built with string concatenation (SQL injection risk)",
            "command_execution": "Potential command injection vulnerability"
        }
        return descriptions.get(anomaly_type, "Unknown anomaly type")

    def _get_severity(self, anomaly_type: str) -> str:
        severity_map = {
            "unsafe_crypto": "high",
            "custom_auth": "high",
            "serialization": "critical",
            "sql_building": "critical",
            "command_execution": "critical"
        }
        return severity_map.get(anomaly_type, "medium")

    def _get_remediation(self, anomaly_type: str) -> str:
        remediations = {
            "unsafe_crypto": "Use modern cryptographic algorithms (AES-256, SHA-256, bcrypt)",
            "custom_auth": "Use well-tested authentication libraries and frameworks",
            "serialization": "Use safe serialization formats (JSON) or validate all input",
            "sql_building": "Use parameterized queries or ORM",
            "command_execution": "Avoid shell=True, use safe subprocess methods"
        }
        return remediations.get(anomaly_type, "Review and update code")
