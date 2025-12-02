"""
GNN Training Pipeline for Vulnerability Detection
Comprehensive training with logging, checkpointing, and evaluation
"""

import os
import json
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict

import torch
import torch.nn as nn
import torch.optim as optim
from torch.optim.lr_scheduler import ReduceLROnPlateau, CosineAnnealingWarmRestarts
import numpy as np

logger = logging.getLogger(__name__)

# Check for PyTorch Geometric
try:
    from torch_geometric.loader import DataLoader
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    TORCH_GEOMETRIC_AVAILABLE = False

# Check for sklearn metrics
try:
    from sklearn.metrics import (
        precision_score, recall_score, f1_score,
        roc_auc_score, average_precision_score,
        classification_report, confusion_matrix
    )
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


@dataclass
class TrainingConfig:
    """Configuration for GNN training"""
    # Model architecture
    num_node_features: int = 10
    hidden_dim: int = 128
    num_classes: int = 25
    num_layers: int = 3
    dropout: float = 0.3

    # Training parameters
    learning_rate: float = 1e-3
    weight_decay: float = 1e-5
    batch_size: int = 32
    num_epochs: int = 100
    patience: int = 15  # Early stopping patience

    # Loss function
    use_focal_loss: bool = True
    focal_gamma: float = 2.0
    class_weights: Optional[List[float]] = None

    # Optimizer
    optimizer: str = "adam"  # adam, adamw, sgd
    scheduler: str = "reduce_on_plateau"  # reduce_on_plateau, cosine

    # Data
    use_codebert: bool = True
    codebert_dim: int = 768

    # Checkpointing
    save_every: int = 5
    checkpoint_dir: str = "checkpoints"

    # Device
    device: str = "auto"

    def get_device(self) -> torch.device:
        if self.device == "auto":
            return torch.device("cuda" if torch.cuda.is_available() else "cpu")
        return torch.device(self.device)


@dataclass
class TrainingMetrics:
    """Metrics tracked during training"""
    epoch: int = 0
    train_loss: float = 0.0
    val_loss: float = 0.0
    train_f1: float = 0.0
    val_f1: float = 0.0
    train_precision: float = 0.0
    val_precision: float = 0.0
    train_recall: float = 0.0
    val_recall: float = 0.0
    train_auc: float = 0.0
    val_auc: float = 0.0
    learning_rate: float = 0.0
    epoch_time: float = 0.0


class FocalLoss(nn.Module):
    """
    Focal Loss for handling class imbalance in vulnerability detection

    Focuses learning on hard examples (rare vulnerability types)
    """

    def __init__(self, gamma: float = 2.0, alpha: Optional[torch.Tensor] = None):
        super().__init__()
        self.gamma = gamma
        self.alpha = alpha

    def forward(self, inputs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        bce_loss = nn.functional.binary_cross_entropy_with_logits(
            inputs, targets, reduction='none'
        )

        pt = torch.exp(-bce_loss)
        focal_weight = (1 - pt) ** self.gamma

        if self.alpha is not None:
            alpha_weight = self.alpha.to(inputs.device) * targets + \
                          (1 - self.alpha.to(inputs.device)) * (1 - targets)
            focal_weight = focal_weight * alpha_weight

        loss = focal_weight * bce_loss
        return loss.mean()


class GNNTrainer:
    """
    Comprehensive GNN training pipeline

    Features:
    - Training with early stopping
    - Validation and evaluation
    - Checkpointing and model versioning
    - Detailed logging and metrics
    - Support for class imbalance (focal loss)
    - Learning rate scheduling
    """

    def __init__(self, config: TrainingConfig):
        self.config = config
        self.device = config.get_device()

        logger.info(f"Initializing GNN Trainer on {self.device}")

        # Initialize model
        self.model = self._build_model()

        # Initialize loss function
        self.criterion = self._build_loss()

        # Initialize optimizer
        self.optimizer = self._build_optimizer()

        # Initialize scheduler
        self.scheduler = self._build_scheduler()

        # Training state
        self.current_epoch = 0
        self.best_val_loss = float('inf')
        self.best_val_f1 = 0.0
        self.epochs_without_improvement = 0
        self.training_history: List[TrainingMetrics] = []

        # Create checkpoint directory
        self.checkpoint_dir = Path(config.checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    def _build_model(self) -> nn.Module:
        """Build the GNN model"""
        try:
            from ..gnn_model import CodeVulnerabilityGNN
        except ImportError:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from gnn_model import CodeVulnerabilityGNN

        # Adjust input features if using CodeBERT
        num_features = self.config.num_node_features
        if self.config.use_codebert:
            num_features += self.config.codebert_dim

        model = CodeVulnerabilityGNN(
            num_node_features=num_features,
            hidden_dim=self.config.hidden_dim,
            num_classes=self.config.num_classes,
            num_layers=self.config.num_layers,
            dropout=self.config.dropout
        )

        return model.to(self.device)

    def _build_loss(self) -> nn.Module:
        """Build loss function"""
        if self.config.use_focal_loss:
            alpha = None
            if self.config.class_weights:
                alpha = torch.FloatTensor(self.config.class_weights)
            return FocalLoss(gamma=self.config.focal_gamma, alpha=alpha)
        else:
            weight = None
            if self.config.class_weights:
                weight = torch.FloatTensor(self.config.class_weights).to(self.device)
            return nn.BCEWithLogitsLoss(weight=weight)

    def _build_optimizer(self) -> optim.Optimizer:
        """Build optimizer"""
        params = self.model.parameters()

        if self.config.optimizer == "adam":
            return optim.Adam(
                params,
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay
            )
        elif self.config.optimizer == "adamw":
            return optim.AdamW(
                params,
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay
            )
        elif self.config.optimizer == "sgd":
            return optim.SGD(
                params,
                lr=self.config.learning_rate,
                momentum=0.9,
                weight_decay=self.config.weight_decay
            )
        else:
            raise ValueError(f"Unknown optimizer: {self.config.optimizer}")

    def _build_scheduler(self):
        """Build learning rate scheduler"""
        if self.config.scheduler == "reduce_on_plateau":
            return ReduceLROnPlateau(
                self.optimizer,
                mode='min',
                factor=0.5,
                patience=5
            )
        elif self.config.scheduler == "cosine":
            return CosineAnnealingWarmRestarts(
                self.optimizer,
                T_0=10,
                T_mult=2
            )
        else:
            return None

    def train(
        self,
        train_loader: Any,
        val_loader: Any,
        resume_from: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Train the model

        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            resume_from: Path to checkpoint to resume from

        Returns:
            Training results dictionary
        """
        logger.info("Starting training...")
        logger.info(f"Config: {asdict(self.config)}")

        # Resume if checkpoint provided
        if resume_from:
            self.load_checkpoint(resume_from)

        # Training loop
        start_time = time.time()

        for epoch in range(self.current_epoch, self.config.num_epochs):
            self.current_epoch = epoch
            epoch_start = time.time()

            # Train one epoch
            train_loss, train_metrics = self._train_epoch(train_loader)

            # Validate
            val_loss, val_metrics = self._validate(val_loader)

            # Update scheduler
            if self.scheduler:
                if isinstance(self.scheduler, ReduceLROnPlateau):
                    self.scheduler.step(val_loss)
                else:
                    self.scheduler.step()

            # Get current learning rate
            current_lr = self.optimizer.param_groups[0]['lr']

            # Record metrics
            epoch_time = time.time() - epoch_start
            metrics = TrainingMetrics(
                epoch=epoch,
                train_loss=train_loss,
                val_loss=val_loss,
                train_f1=train_metrics.get('f1', 0),
                val_f1=val_metrics.get('f1', 0),
                train_precision=train_metrics.get('precision', 0),
                val_precision=val_metrics.get('precision', 0),
                train_recall=train_metrics.get('recall', 0),
                val_recall=val_metrics.get('recall', 0),
                train_auc=train_metrics.get('auc', 0),
                val_auc=val_metrics.get('auc', 0),
                learning_rate=current_lr,
                epoch_time=epoch_time
            )
            self.training_history.append(metrics)

            # Log progress
            logger.info(
                f"Epoch {epoch}/{self.config.num_epochs} - "
                f"Train Loss: {train_loss:.4f}, Val Loss: {val_loss:.4f}, "
                f"Val F1: {val_metrics.get('f1', 0):.4f}, "
                f"LR: {current_lr:.6f}, Time: {epoch_time:.1f}s"
            )

            # Check for improvement
            if val_loss < self.best_val_loss:
                self.best_val_loss = val_loss
                self.best_val_f1 = val_metrics.get('f1', 0)
                self.epochs_without_improvement = 0

                # Save best model
                self.save_checkpoint('best_model.pt', is_best=True)
                logger.info(f"New best model! Val Loss: {val_loss:.4f}")
            else:
                self.epochs_without_improvement += 1

            # Periodic checkpointing
            if (epoch + 1) % self.config.save_every == 0:
                self.save_checkpoint(f'checkpoint_epoch_{epoch}.pt')

            # Early stopping
            if self.epochs_without_improvement >= self.config.patience:
                logger.info(f"Early stopping at epoch {epoch}")
                break

        total_time = time.time() - start_time
        logger.info(f"Training completed in {total_time:.1f}s")

        # Save final model
        self.save_checkpoint('final_model.pt')

        # Return results
        return {
            'best_val_loss': self.best_val_loss,
            'best_val_f1': self.best_val_f1,
            'total_epochs': self.current_epoch + 1,
            'total_time': total_time,
            'training_history': [asdict(m) for m in self.training_history]
        }

    def _train_epoch(self, loader: Any) -> Tuple[float, Dict]:
        """Train for one epoch"""
        self.model.train()

        total_loss = 0
        all_preds = []
        all_labels = []

        for batch in loader:
            batch = batch.to(self.device)

            # Forward pass
            self.optimizer.zero_grad()
            out = self.model(batch.x, batch.edge_index, batch.batch)

            # Reshape y from [batch_size * num_classes] to [batch_size, num_classes]
            # PyG concatenates y tensors when batching graphs
            batch_size = out.size(0)
            num_classes = out.size(1)
            y = batch.y.view(batch_size, num_classes)

            # Compute loss
            loss = self.criterion(out, y)

            # Backward pass
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            self.optimizer.step()

            total_loss += loss.item()

            # Collect predictions
            preds = torch.sigmoid(out).detach().cpu().numpy()
            labels = y.cpu().numpy()
            all_preds.append(preds)
            all_labels.append(labels)

        avg_loss = total_loss / len(loader)
        metrics = self._compute_metrics(
            np.vstack(all_preds),
            np.vstack(all_labels)
        )

        return avg_loss, metrics

    def _validate(self, loader: Any) -> Tuple[float, Dict]:
        """Validate model"""
        self.model.eval()

        total_loss = 0
        all_preds = []
        all_labels = []

        with torch.no_grad():
            for batch in loader:
                batch = batch.to(self.device)

                out = self.model(batch.x, batch.edge_index, batch.batch)

                # Reshape y from [batch_size * num_classes] to [batch_size, num_classes]
                batch_size = out.size(0)
                num_classes = out.size(1)
                y = batch.y.view(batch_size, num_classes)

                loss = self.criterion(out, y)

                total_loss += loss.item()

                preds = torch.sigmoid(out).cpu().numpy()
                labels = y.cpu().numpy()
                all_preds.append(preds)
                all_labels.append(labels)

        avg_loss = total_loss / len(loader)
        metrics = self._compute_metrics(
            np.vstack(all_preds),
            np.vstack(all_labels)
        )

        return avg_loss, metrics

    def _compute_metrics(
        self,
        predictions: np.ndarray,
        labels: np.ndarray,
        threshold: float = 0.5
    ) -> Dict[str, float]:
        """Compute evaluation metrics"""
        if not SKLEARN_AVAILABLE:
            return {}

        # Binary predictions
        binary_preds = (predictions > threshold).astype(int)

        metrics = {}

        try:
            # Macro-averaged metrics
            metrics['precision'] = precision_score(
                labels, binary_preds, average='macro', zero_division=0
            )
            metrics['recall'] = recall_score(
                labels, binary_preds, average='macro', zero_division=0
            )
            metrics['f1'] = f1_score(
                labels, binary_preds, average='macro', zero_division=0
            )

            # Micro-averaged (overall)
            metrics['micro_f1'] = f1_score(
                labels, binary_preds, average='micro', zero_division=0
            )

            # AUC (if applicable)
            if labels.sum() > 0:
                try:
                    metrics['auc'] = roc_auc_score(
                        labels, predictions, average='macro'
                    )
                except ValueError:
                    metrics['auc'] = 0.0

                try:
                    metrics['avg_precision'] = average_precision_score(
                        labels, predictions, average='macro'
                    )
                except ValueError:
                    metrics['avg_precision'] = 0.0

        except Exception as e:
            logger.warning(f"Metrics computation failed: {e}")

        return metrics

    def evaluate(
        self,
        test_loader: Any,
        threshold: float = 0.5
    ) -> Dict[str, Any]:
        """
        Evaluate model on test set

        Returns comprehensive evaluation results
        """
        self.model.eval()

        all_preds = []
        all_labels = []

        with torch.no_grad():
            for batch in test_loader:
                batch = batch.to(self.device)
                out = self.model(batch.x, batch.edge_index, batch.batch)

                # Reshape y from [batch_size * num_classes] to [batch_size, num_classes]
                batch_size = out.size(0)
                num_classes = out.size(1)
                y = batch.y.view(batch_size, num_classes)

                preds = torch.sigmoid(out).cpu().numpy()
                labels = y.cpu().numpy()
                all_preds.append(preds)
                all_labels.append(labels)

        predictions = np.vstack(all_preds)
        labels = np.vstack(all_labels)

        # Overall metrics
        metrics = self._compute_metrics(predictions, labels, threshold)

        # Per-class metrics
        from .data_loader import VULN_TYPES

        per_class = {}
        binary_preds = (predictions > threshold).astype(int)

        for i, vuln_type in enumerate(VULN_TYPES):
            if labels[:, i].sum() > 0:
                per_class[vuln_type] = {
                    'precision': precision_score(labels[:, i], binary_preds[:, i], zero_division=0),
                    'recall': recall_score(labels[:, i], binary_preds[:, i], zero_division=0),
                    'f1': f1_score(labels[:, i], binary_preds[:, i], zero_division=0),
                    'support': int(labels[:, i].sum())
                }

        return {
            'overall': metrics,
            'per_class': per_class,
            'threshold': threshold
        }

    def save_checkpoint(self, filename: str, is_best: bool = False):
        """Save training checkpoint"""
        checkpoint = {
            'epoch': self.current_epoch,
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'scheduler_state_dict': self.scheduler.state_dict() if self.scheduler else None,
            'best_val_loss': self.best_val_loss,
            'best_val_f1': self.best_val_f1,
            'config': asdict(self.config),
            'training_history': [asdict(m) for m in self.training_history],
            'timestamp': datetime.now().isoformat()
        }

        path = self.checkpoint_dir / filename
        torch.save(checkpoint, path)
        logger.info(f"Saved checkpoint: {path}")

        if is_best:
            # Also save just the model weights for deployment
            model_path = self.checkpoint_dir / 'best_model_weights.pt'
            torch.save(self.model.state_dict(), model_path)

    def load_checkpoint(self, path: str):
        """Load training checkpoint"""
        checkpoint = torch.load(path, map_location=self.device)

        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])

        if self.scheduler and checkpoint.get('scheduler_state_dict'):
            self.scheduler.load_state_dict(checkpoint['scheduler_state_dict'])

        self.current_epoch = checkpoint['epoch'] + 1
        self.best_val_loss = checkpoint['best_val_loss']
        self.best_val_f1 = checkpoint.get('best_val_f1', 0)

        logger.info(f"Resumed from epoch {self.current_epoch}")

    def export_for_deployment(self, output_dir: str):
        """
        Export model for deployment

        Creates:
        - Model weights file
        - Config file
        - Metadata file
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Save model weights
        torch.save(
            self.model.state_dict(),
            output_path / 'model.pt'
        )

        # Save config
        with open(output_path / 'config.json', 'w') as f:
            json.dump(asdict(self.config), f, indent=2)

        # Save metadata
        metadata = {
            'created_at': datetime.now().isoformat(),
            'best_val_loss': self.best_val_loss,
            'best_val_f1': self.best_val_f1,
            'total_epochs': self.current_epoch,
            'pytorch_version': torch.__version__,
        }

        with open(output_path / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Exported model for deployment to {output_dir}")

        return output_path
