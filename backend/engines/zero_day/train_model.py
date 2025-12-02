#!/usr/bin/env python3
"""
GNN Model Training and Deployment Script
Usage: python train_model.py [command] [options]

Commands:
  train       - Train a new GNN model
  evaluate    - Evaluate a trained model
  deploy      - Deploy model to registry
  generate    - Generate synthetic training data
  serve       - Start model server
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def cmd_train(args):
    """Train a new GNN model"""
    import torch

    from training.trainer import GNNTrainer, TrainingConfig
    from training.data_loader import create_data_loaders

    logger.info("Starting GNN training...")
    logger.info(f"Data directory: {args.data_dir}")
    logger.info(f"Output directory: {args.output_dir}")

    # Create config
    config = TrainingConfig(
        num_epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        hidden_dim=args.hidden_dim,
        num_layers=args.num_layers,
        dropout=args.dropout,
        use_codebert=args.use_codebert,
        checkpoint_dir=args.output_dir,
        device=args.device
    )

    # Create data loaders
    logger.info("Loading datasets...")
    train_loader, val_loader, test_loader = create_data_loaders(
        data_dir=args.data_dir,
        batch_size=args.batch_size,
        use_codebert=args.use_codebert
    )

    logger.info(f"Train samples: {len(train_loader.dataset)}")
    logger.info(f"Validation samples: {len(val_loader.dataset)}")
    logger.info(f"Test samples: {len(test_loader.dataset)}")

    # Create trainer
    trainer = GNNTrainer(config)

    # Train
    results = trainer.train(
        train_loader=train_loader,
        val_loader=val_loader,
        resume_from=args.resume
    )

    logger.info(f"Training complete!")
    logger.info(f"Best validation loss: {results['best_val_loss']:.4f}")
    logger.info(f"Best validation F1: {results['best_val_f1']:.4f}")

    # Evaluate on test set
    logger.info("Evaluating on test set...")
    test_results = trainer.evaluate(test_loader)

    logger.info("Test Results:")
    logger.info(f"  Precision: {test_results['overall'].get('precision', 0):.4f}")
    logger.info(f"  Recall: {test_results['overall'].get('recall', 0):.4f}")
    logger.info(f"  F1: {test_results['overall'].get('f1', 0):.4f}")

    # Export for deployment
    export_dir = Path(args.output_dir) / 'deployment'
    trainer.export_for_deployment(str(export_dir))

    # Save test results
    with open(export_dir / 'test_results.json', 'w') as f:
        json.dump(test_results, f, indent=2)

    logger.info(f"Model exported to: {export_dir}")


def cmd_evaluate(args):
    """Evaluate a trained model"""
    from training.trainer import GNNTrainer, TrainingConfig
    from training.data_loader import create_data_loaders

    logger.info(f"Evaluating model: {args.model_path}")

    # Load config
    config_path = Path(args.model_path).parent / 'config.json'
    if config_path.exists():
        with open(config_path) as f:
            config_dict = json.load(f)
        config = TrainingConfig(**config_dict)
    else:
        config = TrainingConfig()

    config.checkpoint_dir = str(Path(args.model_path).parent)

    # Create trainer and load model
    trainer = GNNTrainer(config)
    trainer.model.load_state_dict(
        torch.load(args.model_path, map_location=trainer.device)
    )

    # Load test data
    _, _, test_loader = create_data_loaders(
        data_dir=args.data_dir,
        batch_size=args.batch_size
    )

    # Evaluate
    results = trainer.evaluate(test_loader, threshold=args.threshold)

    logger.info("\nEvaluation Results:")
    logger.info(f"  Precision: {results['overall'].get('precision', 0):.4f}")
    logger.info(f"  Recall: {results['overall'].get('recall', 0):.4f}")
    logger.info(f"  F1: {results['overall'].get('f1', 0):.4f}")
    logger.info(f"  AUC: {results['overall'].get('auc', 0):.4f}")

    logger.info("\nPer-class Results:")
    for vuln_type, metrics in results['per_class'].items():
        logger.info(f"  {vuln_type}:")
        logger.info(f"    F1: {metrics['f1']:.4f}, Support: {metrics['support']}")

    # Save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to: {args.output}")


def cmd_deploy(args):
    """Deploy model to registry"""
    from serving.model_server import deploy_model

    logger.info(f"Deploying model: {args.model_path}")
    logger.info(f"Registry: {args.registry_dir}")

    # Load metrics
    metrics = {}
    if args.metrics_file:
        with open(args.metrics_file) as f:
            data = json.load(f)
            metrics = data.get('overall', data)

    # Load config
    config = {}
    config_path = Path(args.model_path).parent / 'config.json'
    if config_path.exists():
        with open(config_path) as f:
            config = json.load(f)

    # Deploy
    metadata = deploy_model(
        model_path=args.model_path,
        registry_dir=args.registry_dir,
        version=args.version,
        metrics=metrics,
        config=config,
        set_as_champion=args.champion,
        description=args.description or f"Model version {args.version}"
    )

    logger.info(f"Deployed successfully!")
    logger.info(f"  Model ID: {metadata.model_id}")
    logger.info(f"  Version: {metadata.version}")
    logger.info(f"  Champion: {metadata.is_champion}")


def cmd_generate(args):
    """Generate synthetic training data"""
    from training.data_loader import SyntheticVulnerabilityDataset

    logger.info(f"Generating {args.num_samples} synthetic samples...")

    generator = SyntheticVulnerabilityDataset()
    generator.save_dataset(
        output_dir=args.output_dir,
        num_samples=args.num_samples
    )

    logger.info(f"Dataset saved to: {args.output_dir}")


def cmd_serve(args):
    """Start model server"""
    from serving.model_server import ModelRegistry, ModelServer

    logger.info(f"Starting model server...")
    logger.info(f"Registry: {args.registry_dir}")

    registry = ModelRegistry(args.registry_dir)
    server = ModelServer(registry, device=args.device)

    stats = server.get_stats()
    logger.info(f"Loaded {stats['loaded_models']} models")
    logger.info(f"Champion: {stats['champion_model']}")

    # Interactive mode for testing
    if args.interactive:
        logger.info("\nInteractive mode. Enter code to analyze (Ctrl+D to exit):")
        while True:
            try:
                print("\nEnter code (empty line to analyze):")
                lines = []
                while True:
                    line = input()
                    if line == '':
                        break
                    lines.append(line)

                if lines:
                    code = '\n'.join(lines)
                    result = server.predict(code)

                    print(f"\nResults ({result['inference_time_ms']:.1f}ms):")
                    if result['vulnerabilities']:
                        for vuln in result['vulnerabilities']:
                            print(f"  - {vuln['type']}: {vuln['confidence']:.2%} ({vuln['severity']})")
                    else:
                        print("  No vulnerabilities detected")

            except EOFError:
                break
            except KeyboardInterrupt:
                break

    logger.info("Server stopped")


def main():
    parser = argparse.ArgumentParser(
        description='GNN Model Training and Deployment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Train command
    train_parser = subparsers.add_parser('train', help='Train a new model')
    train_parser.add_argument('--data-dir', required=True, help='Training data directory')
    train_parser.add_argument('--output-dir', default='./checkpoints', help='Output directory')
    train_parser.add_argument('--epochs', type=int, default=100, help='Number of epochs')
    train_parser.add_argument('--batch-size', type=int, default=32, help='Batch size')
    train_parser.add_argument('--lr', type=float, default=1e-3, help='Learning rate')
    train_parser.add_argument('--hidden-dim', type=int, default=128, help='Hidden dimension')
    train_parser.add_argument('--num-layers', type=int, default=3, help='Number of GNN layers')
    train_parser.add_argument('--dropout', type=float, default=0.3, help='Dropout rate')
    train_parser.add_argument('--use-codebert', action='store_true', help='Use CodeBERT embeddings')
    train_parser.add_argument('--device', default='auto', help='Device (cpu/cuda/auto)')
    train_parser.add_argument('--resume', help='Resume from checkpoint')

    # Evaluate command
    eval_parser = subparsers.add_parser('evaluate', help='Evaluate a model')
    eval_parser.add_argument('--model-path', required=True, help='Path to model weights')
    eval_parser.add_argument('--data-dir', required=True, help='Test data directory')
    eval_parser.add_argument('--batch-size', type=int, default=32, help='Batch size')
    eval_parser.add_argument('--threshold', type=float, default=0.5, help='Prediction threshold')
    eval_parser.add_argument('--output', help='Output file for results')

    # Deploy command
    deploy_parser = subparsers.add_parser('deploy', help='Deploy model to registry')
    deploy_parser.add_argument('--model-path', required=True, help='Path to model weights')
    deploy_parser.add_argument('--registry-dir', required=True, help='Registry directory')
    deploy_parser.add_argument('--version', required=True, help='Version string')
    deploy_parser.add_argument('--metrics-file', help='Metrics JSON file')
    deploy_parser.add_argument('--description', help='Model description')
    deploy_parser.add_argument('--champion', action='store_true', help='Set as champion')

    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate synthetic data')
    gen_parser.add_argument('--output-dir', required=True, help='Output directory')
    gen_parser.add_argument('--num-samples', type=int, default=1000, help='Number of samples')

    # Serve command
    serve_parser = subparsers.add_parser('serve', help='Start model server')
    serve_parser.add_argument('--registry-dir', required=True, help='Registry directory')
    serve_parser.add_argument('--device', default='auto', help='Device')
    serve_parser.add_argument('--interactive', action='store_true', help='Interactive mode')

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # Add parent directory to path for imports
    sys.path.insert(0, str(Path(__file__).parent))

    # Import torch here to allow help without torch installed
    import torch

    commands = {
        'train': cmd_train,
        'evaluate': cmd_evaluate,
        'deploy': cmd_deploy,
        'generate': cmd_generate,
        'serve': cmd_serve
    }

    commands[args.command](args)


if __name__ == '__main__':
    main()
