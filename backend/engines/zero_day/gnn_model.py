"""
Graph Neural Network Model for Vulnerability Detection
Uses PyTorch Geometric for graph-based deep learning
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import List, Dict, Tuple, Optional
import numpy as np
import logging

logger = logging.getLogger(__name__)

# Check if PyTorch Geometric is available
try:
    from torch_geometric.nn import GCNConv, global_mean_pool, global_max_pool
    from torch_geometric.data import Data, Batch
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    logger.warning("PyTorch Geometric not installed. GNN features will be limited.")
    TORCH_GEOMETRIC_AVAILABLE = False


class CodeVulnerabilityGNN(nn.Module):
    """
    Graph Neural Network for code vulnerability detection
    Uses Graph Convolutional Networks (GCN) on Code Property Graphs
    """

    def __init__(
        self,
        num_node_features: int = 10,
        hidden_dim: int = 128,
        num_classes: int = 25,
        num_layers: int = 3,
        dropout: float = 0.3
    ):
        """
        Initialize GNN model

        Args:
            num_node_features: Size of input node feature vectors
            hidden_dim: Hidden layer dimension
            num_classes: Number of vulnerability types to classify
            num_layers: Number of GNN layers
            dropout: Dropout rate for regularization
        """
        super(CodeVulnerabilityGNN, self).__init__()

        if not TORCH_GEOMETRIC_AVAILABLE:
            raise ImportError(
                "PyTorch Geometric required for GNN. "
                "Install: pip install torch-geometric"
            )

        self.num_layers = num_layers
        self.dropout = dropout

        # Input projection
        self.input_proj = nn.Linear(num_node_features, hidden_dim)

        # GNN layers
        self.convs = nn.ModuleList()
        self.batch_norms = nn.ModuleList()

        for i in range(num_layers):
            self.convs.append(GCNConv(hidden_dim, hidden_dim))
            self.batch_norms.append(nn.BatchNorm1d(hidden_dim))

        # Graph-level pooling and classification
        self.pool = global_mean_pool

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),  # *2 for mean+max pooling
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, batch: torch.Tensor):
        """
        Forward pass

        Args:
            x: Node features [num_nodes, num_node_features]
            edge_index: Edge connectivity [2, num_edges]
            batch: Batch assignment for nodes [num_nodes]

        Returns:
            Logits for each vulnerability class [batch_size, num_classes]
        """

        # Project input features
        x = self.input_proj(x)
        x = F.relu(x)

        # Apply GNN layers
        for i in range(self.num_layers):
            x = self.convs[i](x, edge_index)
            x = self.batch_norms[i](x)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)

        # Graph-level pooling (combine mean and max)
        x_mean = global_mean_pool(x, batch)
        x_max = global_max_pool(x, batch)
        x = torch.cat([x_mean, x_max], dim=1)

        # Classification
        out = self.classifier(x)

        return out

    def predict_vulnerabilities(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        threshold: float = 0.5
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Predict vulnerabilities with confidence scores

        Args:
            x: Node features
            edge_index: Edge connectivity
            batch: Batch assignment
            threshold: Confidence threshold for predictions

        Returns:
            Tuple of (predicted_classes, confidence_scores)
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(x, edge_index, batch)
            probs = torch.sigmoid(logits)  # Multi-label classification

            # Get predictions above threshold
            predictions = (probs > threshold).float()
            confidence = probs

        return predictions, confidence


class SimpleVulnerabilityClassifier(nn.Module):
    """
    Fallback classifier when PyTorch Geometric is not available
    Uses simple MLP on aggregated graph features
    """

    def __init__(
        self,
        input_dim: int = 100,
        hidden_dim: int = 128,
        num_classes: int = 25
    ):
        super(SimpleVulnerabilityClassifier, self).__init__()

        self.network = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, x: torch.Tensor):
        return self.network(x)


class VulnerabilityDetector:
    """
    High-level vulnerability detector using GNN
    Handles model loading, inference, and result formatting
    """

    def __init__(self, model_path: Optional[str] = None, device: str = "cpu"):
        """
        Initialize detector

        Args:
            model_path: Path to pre-trained model weights
            device: Device to run model on ('cpu' or 'cuda')
        """
        self.device = torch.device(device)

        # Initialize model
        if TORCH_GEOMETRIC_AVAILABLE:
            self.model = CodeVulnerabilityGNN(
                num_node_features=10,
                hidden_dim=128,
                num_classes=25,
                num_layers=3
            ).to(self.device)
        else:
            logger.warning("Using simple classifier (PyTorch Geometric not available)")
            self.model = SimpleVulnerabilityClassifier(
                input_dim=100,
                hidden_dim=128,
                num_classes=25
            ).to(self.device)

        # Load pre-trained weights if available
        if model_path:
            try:
                self.model.load_state_dict(torch.load(model_path, map_location=self.device))
                logger.info(f"Loaded model from {model_path}")
            except Exception as e:
                logger.warning(f"Could not load model: {str(e)}. Using untrained model.")

        self.model.eval()

        # Vulnerability type mapping
        self.vulnerability_types = [
            "sql_injection",
            "command_injection",
            "path_traversal",
            "xss",
            "unsafe_deserialization",
            "weak_crypto",
            "hardcoded_secrets",
            "insecure_random",
            "buffer_overflow",
            "use_after_free",
            "null_pointer_dereference",
            "race_condition",
            "resource_exhaustion",
            "memory_leak",
            "sensitive_data_exposure",
            "xxe",
            "ssrf",
            "ldap_injection",
            "xpath_injection",
            "code_injection",
            "authentication_bypass",
            "authorization_bypass",
            "session_fixation",
            "csrf",
            "open_redirect"
        ]

    def detect(
        self,
        graph_features: Dict[str, any],
        threshold: float = 0.5
    ) -> List[Dict]:
        """
        Detect vulnerabilities from graph features

        Args:
            graph_features: Dictionary with node_features, edge_indices, etc.
            threshold: Confidence threshold

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        try:
            # Prepare data
            if TORCH_GEOMETRIC_AVAILABLE:
                data = self._prepare_torch_geometric_data(graph_features)
                predictions, confidences = self.model.predict_vulnerabilities(
                    data.x,
                    data.edge_index,
                    data.batch,
                    threshold
                )
            else:
                # Fallback: use aggregated features
                features = self._aggregate_features(graph_features)
                features_tensor = torch.FloatTensor(features).unsqueeze(0).to(self.device)

                self.model.eval()
                with torch.no_grad():
                    logits = self.model(features_tensor)
                    probs = torch.sigmoid(logits)
                    predictions = (probs > threshold).float()
                    confidences = probs

            # Convert predictions to vulnerability list
            predictions_np = predictions.cpu().numpy()[0]
            confidences_np = confidences.cpu().numpy()[0]

            for i, (pred, conf) in enumerate(zip(predictions_np, confidences_np)):
                if pred > 0:  # Vulnerability detected
                    vulnerabilities.append({
                        'type': self.vulnerability_types[i],
                        'confidence': float(conf),
                        'severity': self._map_severity(self.vulnerability_types[i]),
                        'category': 'Security'
                    })

        except Exception as e:
            logger.error(f"Error during vulnerability detection: {str(e)}")

        return vulnerabilities

    def _prepare_torch_geometric_data(self, graph_features: Dict) -> Data:
        """Convert graph features to PyTorch Geometric Data object"""

        node_features = torch.FloatTensor(graph_features['node_features']).to(self.device)

        # Handle edge indices
        if graph_features['edge_indices']:
            edge_index = torch.LongTensor(graph_features['edge_indices']).t().to(self.device)
        else:
            # Empty graph - create self-loops
            num_nodes = len(graph_features['node_features'])
            edge_index = torch.LongTensor([[i, i] for i in range(num_nodes)]).t().to(self.device)

        # Create batch (single graph)
        batch = torch.zeros(len(graph_features['node_features']), dtype=torch.long).to(self.device)

        data = Data(x=node_features, edge_index=edge_index, batch=batch)

        return data

    def _aggregate_features(self, graph_features: Dict) -> List[float]:
        """
        Aggregate graph features for simple classifier

        Creates fixed-size feature vector from variable-size graph
        """
        features = [0.0] * 100  # Fixed size

        node_features = graph_features['node_features']

        if not node_features:
            return features

        # Convert to numpy for easier manipulation
        node_features_np = np.array(node_features)

        # Statistical aggregations
        features[0:10] = np.mean(node_features_np, axis=0).tolist()  # Mean
        features[10:20] = np.max(node_features_np, axis=0).tolist()  # Max
        features[20:30] = np.min(node_features_np, axis=0).tolist()  # Min
        features[30:40] = np.std(node_features_np, axis=0).tolist()  # Std

        # Graph statistics
        num_nodes = len(node_features)
        num_edges = len(graph_features.get('edge_indices', []))

        features[40] = min(num_nodes / 1000.0, 1.0)  # Normalized node count
        features[41] = min(num_edges / 1000.0, 1.0)  # Normalized edge count

        if num_nodes > 0:
            features[42] = num_edges / num_nodes  # Edge-to-node ratio

        return features

    def _map_severity(self, vuln_type: str) -> str:
        """Map vulnerability type to severity level"""

        critical_types = [
            'sql_injection',
            'command_injection',
            'unsafe_deserialization',
            'authentication_bypass',
            'authorization_bypass',
            'buffer_overflow'
        ]

        high_types = [
            'xss',
            'path_traversal',
            'weak_crypto',
            'hardcoded_secrets',
            'ssrf',
            'xxe',
            'code_injection'
        ]

        if vuln_type in critical_types:
            return 'critical'
        elif vuln_type in high_types:
            return 'high'
        else:
            return 'medium'
