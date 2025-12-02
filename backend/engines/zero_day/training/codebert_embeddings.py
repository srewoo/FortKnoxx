"""
CodeBERT Integration for Enhanced Code Embeddings
Uses Microsoft's CodeBERT model for semantic code understanding
"""

import torch
import logging
from typing import List, Optional, Tuple
import numpy as np

logger = logging.getLogger(__name__)

# Check for transformers
try:
    from transformers import AutoTokenizer, AutoModel
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    logger.warning("Transformers not available. Install: pip install transformers")
    TRANSFORMERS_AVAILABLE = False


class CodeBERTEmbedder:
    """
    Generate code embeddings using CodeBERT

    CodeBERT is pre-trained on code-text pairs and understands
    both natural language and programming language semantics.
    """

    def __init__(
        self,
        model_name: str = "microsoft/codebert-base",
        device: Optional[str] = None,
        max_length: int = 512
    ):
        """
        Initialize CodeBERT embedder

        Args:
            model_name: HuggingFace model name
            device: Device to run on ('cpu', 'cuda', or None for auto)
            max_length: Maximum sequence length
        """
        if not TRANSFORMERS_AVAILABLE:
            raise ImportError("transformers library required. Install: pip install transformers")

        self.max_length = max_length

        # Determine device
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        logger.info(f"Loading CodeBERT model: {model_name}")
        logger.info(f"Using device: {self.device}")

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModel.from_pretrained(model_name)
            self.model.to(self.device)
            self.model.eval()

            self.embedding_dim = self.model.config.hidden_size  # Usually 768
            logger.info(f"CodeBERT loaded successfully. Embedding dim: {self.embedding_dim}")

        except Exception as e:
            logger.error(f"Failed to load CodeBERT: {e}")
            raise

    def get_code_embedding(self, code: str) -> np.ndarray:
        """
        Get embedding for entire code snippet

        Args:
            code: Source code string

        Returns:
            Numpy array of shape (embedding_dim,)
        """
        with torch.no_grad():
            # Tokenize
            inputs = self.tokenizer(
                code,
                return_tensors="pt",
                max_length=self.max_length,
                truncation=True,
                padding=True
            ).to(self.device)

            # Get model output
            outputs = self.model(**inputs)

            # Use [CLS] token embedding as code representation
            embedding = outputs.last_hidden_state[:, 0, :].cpu().numpy()

            return embedding.squeeze()

    def get_token_embeddings(self, code: str) -> Tuple[List[str], np.ndarray]:
        """
        Get embeddings for each token in code

        Args:
            code: Source code string

        Returns:
            Tuple of (tokens, embeddings) where embeddings is (num_tokens, embedding_dim)
        """
        with torch.no_grad():
            # Tokenize
            inputs = self.tokenizer(
                code,
                return_tensors="pt",
                max_length=self.max_length,
                truncation=True,
                padding=True
            ).to(self.device)

            # Get tokens
            tokens = self.tokenizer.convert_ids_to_tokens(inputs['input_ids'][0])

            # Get model output
            outputs = self.model(**inputs)

            # All token embeddings
            embeddings = outputs.last_hidden_state.cpu().numpy().squeeze()

            return tokens, embeddings

    def get_node_embeddings(
        self,
        code: str,
        num_nodes: int,
        pooling: str = "mean"
    ) -> List[List[float]]:
        """
        Get embeddings suitable for graph nodes

        Maps code embeddings to graph node features by:
        1. Getting token embeddings from CodeBERT
        2. Pooling/distributing to match number of graph nodes

        Args:
            code: Source code string
            num_nodes: Number of nodes in graph
            pooling: Pooling strategy ('mean', 'first', 'distribute')

        Returns:
            List of embedding vectors, one per node
        """
        if num_nodes == 0:
            return []

        with torch.no_grad():
            # Get token embeddings
            tokens, embeddings = self.get_token_embeddings(code)

            # Remove special tokens ([CLS], [SEP], [PAD])
            # Keep only actual code tokens
            valid_mask = [
                t not in ['[CLS]', '[SEP]', '[PAD]', '<s>', '</s>', '<pad>']
                for t in tokens
            ]
            valid_embeddings = embeddings[valid_mask]

            if len(valid_embeddings) == 0:
                # Fallback to mean of all embeddings
                valid_embeddings = embeddings

            # Match to number of nodes
            if pooling == "mean":
                # All nodes get the same mean embedding
                mean_emb = np.mean(valid_embeddings, axis=0).tolist()
                return [mean_emb for _ in range(num_nodes)]

            elif pooling == "first":
                # All nodes get the first (CLS-like) embedding
                first_emb = embeddings[0].tolist()
                return [first_emb for _ in range(num_nodes)]

            elif pooling == "distribute":
                # Distribute embeddings across nodes
                node_embeddings = []
                num_valid = len(valid_embeddings)

                for i in range(num_nodes):
                    # Map node index to token index
                    token_idx = int((i / num_nodes) * num_valid)
                    token_idx = min(token_idx, num_valid - 1)
                    node_embeddings.append(valid_embeddings[token_idx].tolist())

                return node_embeddings

            else:
                raise ValueError(f"Unknown pooling strategy: {pooling}")

    def get_function_embeddings(self, code: str) -> List[Tuple[str, np.ndarray]]:
        """
        Get embeddings for each function in code

        Args:
            code: Source code string

        Returns:
            List of (function_name, embedding) tuples
        """
        import ast

        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

        function_embeddings = []
        lines = code.split('\n')

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Extract function code
                start_line = node.lineno - 1
                end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line + 10

                func_code = '\n'.join(lines[start_line:end_line])

                # Get embedding
                embedding = self.get_code_embedding(func_code)
                function_embeddings.append((node.name, embedding))

        return function_embeddings

    def compute_similarity(
        self,
        code1: str,
        code2: str
    ) -> float:
        """
        Compute semantic similarity between two code snippets

        Args:
            code1: First code snippet
            code2: Second code snippet

        Returns:
            Cosine similarity score (0-1)
        """
        emb1 = self.get_code_embedding(code1)
        emb2 = self.get_code_embedding(code2)

        # Cosine similarity
        similarity = np.dot(emb1, emb2) / (np.linalg.norm(emb1) * np.linalg.norm(emb2))

        return float(similarity)

    def find_similar_code(
        self,
        query_code: str,
        code_database: List[str],
        top_k: int = 5
    ) -> List[Tuple[int, float, str]]:
        """
        Find most similar code snippets in database

        Args:
            query_code: Code to search for
            code_database: List of code snippets to search in
            top_k: Number of results to return

        Returns:
            List of (index, similarity, code) tuples
        """
        query_emb = self.get_code_embedding(query_code)

        similarities = []
        for i, code in enumerate(code_database):
            emb = self.get_code_embedding(code)
            sim = np.dot(query_emb, emb) / (np.linalg.norm(query_emb) * np.linalg.norm(emb))
            similarities.append((i, sim, code))

        # Sort by similarity
        similarities.sort(key=lambda x: x[1], reverse=True)

        return similarities[:top_k]


class CodeBERTVulnerabilityClassifier:
    """
    Fine-tuned CodeBERT for vulnerability classification
    Can be used standalone or combined with GNN
    """

    def __init__(
        self,
        num_classes: int = 25,
        model_name: str = "microsoft/codebert-base",
        device: Optional[str] = None
    ):
        if not TRANSFORMERS_AVAILABLE:
            raise ImportError("transformers required")

        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        self.num_classes = num_classes

        # Load CodeBERT
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.encoder = AutoModel.from_pretrained(model_name)

        # Classification head
        hidden_size = self.encoder.config.hidden_size
        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(hidden_size, hidden_size),
            torch.nn.ReLU(),
            torch.nn.Dropout(0.1),
            torch.nn.Linear(hidden_size, num_classes)
        )

        self.encoder.to(self.device)
        self.classifier.to(self.device)

    def forward(self, code: str) -> torch.Tensor:
        """Forward pass for single code snippet"""
        inputs = self.tokenizer(
            code,
            return_tensors="pt",
            max_length=512,
            truncation=True,
            padding=True
        ).to(self.device)

        with torch.no_grad():
            outputs = self.encoder(**inputs)
            cls_embedding = outputs.last_hidden_state[:, 0, :]

        logits = self.classifier(cls_embedding)
        return logits

    def predict(self, code: str, threshold: float = 0.5) -> List[Tuple[str, float]]:
        """
        Predict vulnerabilities in code

        Returns:
            List of (vulnerability_type, confidence) tuples
        """
        from .data_loader import VULN_TYPES

        self.encoder.eval()
        self.classifier.eval()

        logits = self.forward(code)
        probs = torch.sigmoid(logits).cpu().numpy().squeeze()

        predictions = []
        for i, prob in enumerate(probs):
            if prob > threshold:
                predictions.append((VULN_TYPES[i], float(prob)))

        return sorted(predictions, key=lambda x: x[1], reverse=True)

    def save(self, path: str):
        """Save model weights"""
        torch.save({
            'encoder_state': self.encoder.state_dict(),
            'classifier_state': self.classifier.state_dict()
        }, path)

    def load(self, path: str):
        """Load model weights"""
        checkpoint = torch.load(path, map_location=self.device)
        self.encoder.load_state_dict(checkpoint['encoder_state'])
        self.classifier.load_state_dict(checkpoint['classifier_state'])
