"""
Data Loading and Preprocessing for GNN Training
Handles vulnerability datasets and converts them to graph format
"""

import os
import json
import torch
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
import random

logger = logging.getLogger(__name__)

# Check for PyTorch Geometric
try:
    from torch_geometric.data import Data, Dataset, InMemoryDataset
    from torch_geometric.loader import DataLoader
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    logger.warning("PyTorch Geometric not available. Install: pip install torch-geometric")
    TORCH_GEOMETRIC_AVAILABLE = False
    Data = object
    Dataset = object
    InMemoryDataset = object


@dataclass
class VulnerabilityLabel:
    """Vulnerability label with metadata"""
    vuln_type: str
    severity: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None


# Vulnerability type to index mapping
VULN_TYPES = [
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

VULN_TO_IDX = {vuln: idx for idx, vuln in enumerate(VULN_TYPES)}
NUM_CLASSES = len(VULN_TYPES)


class VulnerabilityDataset(InMemoryDataset if TORCH_GEOMETRIC_AVAILABLE else object):
    """
    Dataset for vulnerability detection training

    Expects data in format:
    - data_dir/
        - samples/
            - sample_001.json  # Contains code, graph features, labels
            - sample_002.json
            ...
        - metadata.json  # Dataset metadata
    """

    def __init__(
        self,
        root: str,
        split: str = "train",
        transform=None,
        pre_transform=None,
        use_codebert: bool = True
    ):
        """
        Initialize dataset

        Args:
            root: Root directory of dataset
            split: One of 'train', 'val', 'test'
            transform: PyG transform to apply
            pre_transform: PyG pre-transform to apply
            use_codebert: Whether to use CodeBERT embeddings
        """
        self.split = split
        self.use_codebert = use_codebert
        self._codebert_embedder = None

        if not TORCH_GEOMETRIC_AVAILABLE:
            raise ImportError("PyTorch Geometric required for VulnerabilityDataset")

        super().__init__(root, transform, pre_transform)
        self.data, self.slices = torch.load(self.processed_paths[0], weights_only=False)

    @property
    def raw_file_names(self) -> List[str]:
        """Required by InMemoryDataset"""
        return ['samples']

    @property
    def processed_file_names(self) -> List[str]:
        """Processed file for each split"""
        return [f'{self.split}_data.pt']

    @property
    def codebert_embedder(self):
        """Lazy load CodeBERT embedder"""
        if self._codebert_embedder is None and self.use_codebert:
            try:
                from .codebert_embeddings import CodeBERTEmbedder
                self._codebert_embedder = CodeBERTEmbedder()
            except Exception as e:
                logger.warning(f"Could not load CodeBERT: {e}")
                self.use_codebert = False
        return self._codebert_embedder

    def download(self):
        """Download not implemented - use prepare_dataset.py"""
        pass

    def process(self):
        """Process raw data into PyG format"""
        samples_dir = Path(self.raw_dir) / 'samples'

        if not samples_dir.exists():
            logger.warning(f"No samples directory found at {samples_dir}")
            # Create empty dataset
            data_list = []
            data, slices = self.collate(data_list)
            torch.save((data, slices), self.processed_paths[0])
            return

        # Load metadata
        metadata_path = Path(self.raw_dir) / 'metadata.json'
        metadata = {}
        if metadata_path.exists():
            with open(metadata_path) as f:
                metadata = json.load(f)

        # Get split file list
        split_files = self._get_split_files(samples_dir, metadata)

        # Process each sample
        data_list = []
        for sample_file in split_files:
            try:
                sample_path = samples_dir / sample_file
                with open(sample_path) as f:
                    sample = json.load(f)

                data = self._process_sample(sample)
                if data is not None:
                    data_list.append(data)

            except Exception as e:
                logger.warning(f"Error processing {sample_file}: {e}")

        logger.info(f"Processed {len(data_list)} samples for {self.split} split")

        if self.pre_transform:
            data_list = [self.pre_transform(d) for d in data_list]

        data, slices = self.collate(data_list)
        torch.save((data, slices), self.processed_paths[0])

    def _get_split_files(self, samples_dir: Path, metadata: Dict) -> List[str]:
        """Get files for this split"""
        all_files = list(samples_dir.glob("*.json"))

        # Check if splits are defined in metadata
        if 'splits' in metadata and self.split in metadata['splits']:
            return metadata['splits'][self.split]

        # Default: random split 80/10/10
        random.seed(42)  # Reproducible splits
        random.shuffle(all_files)

        n = len(all_files)
        train_end = int(0.8 * n)
        val_end = int(0.9 * n)

        if self.split == 'train':
            return [f.name for f in all_files[:train_end]]
        elif self.split == 'val':
            return [f.name for f in all_files[train_end:val_end]]
        else:  # test
            return [f.name for f in all_files[val_end:]]

    def _process_sample(self, sample: Dict) -> Optional[Data]:
        """Convert sample dict to PyG Data object"""

        # Extract node features
        if 'node_features' in sample:
            node_features = sample['node_features']
        elif 'code' in sample:
            # Generate features from code using CPG extractor
            node_features = self._extract_features_from_code(sample['code'])
        else:
            logger.warning("Sample missing both node_features and code")
            return None

        if not node_features:
            return None

        # Enhance with CodeBERT if available
        if self.use_codebert and 'code' in sample and self.codebert_embedder:
            try:
                codebert_features = self.codebert_embedder.get_node_embeddings(
                    sample['code'],
                    len(node_features)
                )
                # Concatenate CodeBERT features
                node_features = [
                    nf + cbf for nf, cbf in zip(node_features, codebert_features)
                ]
            except Exception as e:
                logger.debug(f"CodeBERT embedding failed: {e}")

        x = torch.FloatTensor(node_features)

        # Extract edge indices
        edge_indices = sample.get('edge_indices', [])
        if edge_indices:
            edge_index = torch.LongTensor(edge_indices).t().contiguous()
        else:
            # Self-loops for empty graphs
            num_nodes = len(node_features)
            edge_index = torch.stack([
                torch.arange(num_nodes),
                torch.arange(num_nodes)
            ])

        # Extract labels (multi-label)
        labels = sample.get('labels', [])
        y = torch.zeros(NUM_CLASSES)
        for label in labels:
            if isinstance(label, str):
                vuln_type = label
            elif isinstance(label, dict):
                vuln_type = label.get('vuln_type', label.get('type', ''))
            else:
                continue

            if vuln_type in VULN_TO_IDX:
                y[VULN_TO_IDX[vuln_type]] = 1.0

        # Create PyG Data object
        data = Data(
            x=x,
            edge_index=edge_index,
            y=y
        )

        # Optional: add file path for debugging
        if 'file_path' in sample:
            data.file_path = sample['file_path']

        return data

    def _extract_features_from_code(self, code: str) -> List[List[float]]:
        """Extract features from code using CPG extractor"""
        try:
            from ..code_graph_extractor import CodeGraphExtractor
            extractor = CodeGraphExtractor()
            cpg = extractor.create_code_property_graph(code)
            features = extractor.extract_features(cpg)
            return features.get('node_features', [])
        except Exception as e:
            logger.warning(f"Feature extraction failed: {e}")
            return []


def create_data_loaders(
    data_dir: str,
    batch_size: int = 32,
    num_workers: int = 4,
    use_codebert: bool = True
) -> Tuple[Any, Any, Any]:
    """
    Create train, validation, and test data loaders

    Args:
        data_dir: Path to dataset directory
        batch_size: Batch size for training
        num_workers: Number of data loading workers
        use_codebert: Whether to use CodeBERT embeddings

    Returns:
        Tuple of (train_loader, val_loader, test_loader)
    """
    if not TORCH_GEOMETRIC_AVAILABLE:
        raise ImportError("PyTorch Geometric required")

    train_dataset = VulnerabilityDataset(
        root=data_dir,
        split='train',
        use_codebert=use_codebert
    )

    val_dataset = VulnerabilityDataset(
        root=data_dir,
        split='val',
        use_codebert=use_codebert
    )

    test_dataset = VulnerabilityDataset(
        root=data_dir,
        split='test',
        use_codebert=use_codebert
    )

    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=num_workers
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers
    )

    test_loader = DataLoader(
        test_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers
    )

    return train_loader, val_loader, test_loader


class SyntheticVulnerabilityDataset:
    """
    Generate synthetic training data from known vulnerability patterns
    Useful for bootstrapping when real labeled data is scarce
    """

    def __init__(self):
        self.vulnerability_templates = self._load_templates()

    def _load_templates(self) -> Dict[str, List[str]]:
        """Load vulnerability code templates (now with enhanced diversity)"""
        try:
            from .enhanced_templates import get_all_templates
            return get_all_templates()
        except ImportError:
            # Fallback to basic templates if enhanced not available
            return self._get_basic_templates()

    def _get_basic_templates(self) -> Dict[str, List[str]]:
        """Fallback basic templates"""
        return {
            "sql_injection": [
                '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
''',
                '''
def search_users(name):
    query = f"SELECT * FROM users WHERE name LIKE '%{name}%'"
    return db.execute(query)
''',
            ],
            "command_injection": [
                '''
import os
def run_command(cmd):
    os.system(cmd)
''',
                '''
import subprocess
def execute(user_input):
    subprocess.call(user_input, shell=True)
''',
            ],
            "path_traversal": [
                '''
def read_file(filename):
    with open("/data/" + filename) as f:
        return f.read()
''',
            ],
            "xss": [
                '''
def render_page(user_content):
    return f"<html><body>{user_content}</body></html>"
''',
            ],
            "unsafe_deserialization": [
                '''
import pickle
def load_data(data):
    return pickle.loads(data)
''',
                '''
def deserialize(data):
    return eval(data)
''',
            ],
            "weak_crypto": [
                '''
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
''',
            ],
            "hardcoded_secrets": [
                '''
API_KEY = "sk-1234567890abcdef"
def authenticate():
    return API_KEY
''',
            ],
        }

    def generate_samples(self, num_samples: int = 1000) -> List[Dict]:
        """Generate synthetic training samples"""
        samples = []

        # Handle both package and direct script execution
        try:
            from ..code_graph_extractor import CodeGraphExtractor
        except ImportError:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from code_graph_extractor import CodeGraphExtractor

        extractor = CodeGraphExtractor()

        for _ in range(num_samples):
            # Pick random vulnerability type
            vuln_type = random.choice(list(self.vulnerability_templates.keys()))
            templates = self.vulnerability_templates[vuln_type]
            code = random.choice(templates)

            # Add some variation
            code = self._add_variation(code)

            # Extract features
            try:
                cpg = extractor.create_code_property_graph(code)
                features = extractor.extract_features(cpg)

                sample = {
                    'code': code,
                    'node_features': features['node_features'],
                    'edge_indices': features['edge_indices'],
                    'labels': [vuln_type],
                    'synthetic': True
                }
                samples.append(sample)

            except Exception as e:
                logger.debug(f"Failed to process template: {e}")

        return samples

    def _add_variation(self, code: str) -> str:
        """Add random variations to code"""
        # Simple variations - rename variables, add comments
        variations = [
            ("user_id", "uid"),
            ("user_input", "input_data"),
            ("name", "username"),
            ("data", "payload"),
        ]

        for old, new in variations:
            if random.random() > 0.5:
                code = code.replace(old, new)

        # Maybe add a comment
        if random.random() > 0.7:
            code = "# Processing function\n" + code

        return code

    def save_dataset(self, output_dir: str, num_samples: int = 1000):
        """Save generated dataset to disk"""
        output_path = Path(output_dir)
        samples_dir = output_path / 'raw' / 'samples'
        samples_dir.mkdir(parents=True, exist_ok=True)

        samples = self.generate_samples(num_samples)

        for i, sample in enumerate(samples):
            sample_file = samples_dir / f"sample_{i:05d}.json"
            with open(sample_file, 'w') as f:
                json.dump(sample, f, indent=2)

        # Save metadata
        metadata = {
            'num_samples': len(samples),
            'vuln_types': list(self.vulnerability_templates.keys()),
            'synthetic': True
        }

        with open(output_path / 'raw' / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Saved {len(samples)} synthetic samples to {output_dir}")
