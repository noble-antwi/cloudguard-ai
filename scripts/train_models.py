"""
Model Training Script
Trains both Isolation Forest (anomaly detection) and Random Forest (classification) models.
Compares performance and saves best models.
"""

import logging
import json
import argparse
from pathlib import Path
from datetime import datetime
import numpy as np
import pandas as pd
from typing import Dict

# Import our modules
import sys
sys.path.insert(0, 'src')

from data.data_ingestion import CloudTrailIngestion
from data.data_preprocessing import DataPreprocessor
from data.feature_engineering import FeatureEngineer
from models.anomaly_detector import AnomalyDetector
from models.threat_classifier import ThreatClassifier

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_labeled_dataset(events_file: str, labels_file: str) -> tuple:
    """
    Load labeled CloudTrail dataset.
    
    Args:
        events_file: Path to CloudTrail events JSON
        labels_file: Path to labels JSON
        
    Returns:
        Tuple of (DataFrame, labels array, labels_data dict)
    """
    logger.info(f"Loading labeled dataset from {events_file}")
    
    # Load events
    ingester = CloudTrailIngestion()
    with open(events_file, 'r') as f:
        data = json.load(f)
        events = data['Records']
    
    # Load labels
    with open(labels_file, 'r') as f:
        labels_data = json.load(f)
    
    # Convert to DataFrame
    df = ingester.events_to_dataframe(events)
    
    logger.info(f"Loaded {len(df)} events")
    logger.info(f"Label distribution: {labels_data['statistics']}")
    
    return df, labels_data


def prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Preprocess and extract features from CloudTrail data.
    
    Args:
        df: Raw CloudTrail DataFrame
        
    Returns:
        DataFrame with extracted features
    """
    logger.info("Preprocessing data...")
    preprocessor = DataPreprocessor()
    df_clean = preprocessor.clean_data(df)
    
    logger.info("Extracting features...")
    engineer = FeatureEngineer()
    df_features = engineer.extract_features(df_clean)
    
    logger.info(f"Feature extraction complete. Shape: {df_features.shape}")
    
    return df_features, engineer


def train_anomaly_detector(
    df_features: pd.DataFrame,
    feature_engineer: FeatureEngineer,
    save_path: str
) -> Dict:
    """
    Train Isolation Forest anomaly detector.
    
    Args:
        df_features: DataFrame with features
        feature_engineer: Feature engineer instance
        save_path: Path to save model
        
    Returns:
        Dictionary with training results
    """
    logger.info("\n" + "="*70)
    logger.info("TRAINING ISOLATION FOREST (ANOMALY DETECTION)")
    logger.info("="*70)
    
    # Get feature columns
    feature_cols = feature_engineer.get_feature_columns()
    
    # Train model
    detector = AnomalyDetector()
    detector.train(df_features, feature_cols=feature_cols)
    
    # Detect anomalies
    anomalies, scores = detector.detect_anomalies(df_features, threshold=0.7)
    
    # Calculate statistics
    anomaly_rate = len(anomalies) / len(df_features) * 100
    
    results = {
        'model_type': 'isolation_forest',
        'total_samples': len(df_features),
        'anomalies_detected': len(anomalies),
        'anomaly_rate': anomaly_rate,
        'mean_anomaly_score': float(scores[scores >= 0.7].mean()) if len(scores[scores >= 0.7]) > 0 else 0,
        'n_features': len(feature_cols)
    }
    
    # Save model
    detector.save_model(save_path)
    logger.info(f"Model saved to {save_path}")
    
    logger.info(f"\nResults:")
    logger.info(f"  Total samples: {results['total_samples']}")
    logger.info(f"  Anomalies detected: {results['anomalies_detected']}")
    logger.info(f"  Anomaly rate: {results['anomaly_rate']:.2f}%")
    logger.info(f"  Mean anomaly score: {results['mean_anomaly_score']:.3f}")
    
    return results, detector


def train_threat_classifier(
    df_features: pd.DataFrame,
    labels_data: Dict,
    feature_engineer: FeatureEngineer,
    save_path: str
) -> Dict:
    """
    Train Random Forest threat classifier.
    
    Args:
        df_features: DataFrame with features
        labels_data: Dictionary with event labels
        feature_engineer: Feature engineer instance
        save_path: Path to save model
        
    Returns:
        Dictionary with training results
    """
    logger.info("\n" + "="*70)
    logger.info("TRAINING RANDOM FOREST (THREAT CLASSIFICATION)")
    logger.info("="*70)
    
    # Get labels
    y = np.array([
        labels_data['event_labels'][event_id]['label']
        for event_id in df_features['eventID']
    ])
    
    # Get feature columns
    feature_cols = feature_engineer.get_feature_columns()
    
    # Train model
    classifier = ThreatClassifier()
    training_metrics = classifier.train(df_features, y, feature_cols, validation_split=0.2)
    
    # Evaluate on full dataset
    full_metrics = classifier.evaluate(df_features, y)
    
    # Print detailed report
    classifier.print_classification_report(df_features, y)
    
    # Classify threats
    results = classifier.classify_threats(df_features, confidence_threshold=0.7)
    high_confidence_threats = results[
        (results['predicted_type'] != 'normal') & 
        (results['high_confidence'])
    ]
    
    training_results = {
        'model_type': 'random_forest',
        'total_samples': len(df_features),
        'validation_accuracy': training_metrics['validation_metrics']['accuracy'],
        'validation_f1': training_metrics['validation_metrics']['f1_macro'],
        'cv_f1_mean': training_metrics['cv_f1_mean'],
        'cv_f1_std': training_metrics['cv_f1_std'],
        'threats_detected': len(high_confidence_threats),
        'n_features': len(feature_cols),
        'feature_importances': training_metrics['feature_importances']
    }
    
    # Save model
    classifier.save_model(save_path)
    logger.info(f"Model saved to {save_path}")
    
    return training_results, classifier


def compare_models(
    anomaly_results: Dict,
    classifier_results: Dict,
    df_features: pd.DataFrame,
    labels_data: Dict,
    anomaly_detector: AnomalyDetector,
    threat_classifier: ThreatClassifier
) -> None:
    """
    Compare performance of both models.
    
    Args:
        anomaly_results: Isolation Forest results
        classifier_results: Random Forest results
        df_features: DataFrame with features
        labels_data: Labels data
        anomaly_detector: Trained anomaly detector
        threat_classifier: Trained threat classifier
    """
    logger.info("\n" + "="*70)
    logger.info("MODEL COMPARISON")
    logger.info("="*70)
    
    # Get true labels
    y_true = np.array([
        labels_data['event_labels'][event_id]['label']
        for event_id in df_features['eventID']
    ])
    
    # Convert to binary (attack vs normal)
    y_true_binary = (y_true != 0).astype(int)
    
    # Get predictions from both models
    # Anomaly detector
    anomaly_predictions = anomaly_detector.predict(df_features)
    anomaly_pred_binary = (anomaly_predictions == -1).astype(int)
    
    # Threat classifier
    classifier_predictions = threat_classifier.predict(df_features)
    classifier_pred_binary = (classifier_predictions != 0).astype(int)
    
    # Calculate metrics for both
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    
    print("\n" + "="*70)
    print("BINARY CLASSIFICATION (Attack vs Normal)")
    print("="*70)
    print(f"\n{'Metric':<25} {'Isolation Forest':>20} {'Random Forest':>20}")
    print("-"*70)
    
    metrics = [
        ('Accuracy', accuracy_score),
        ('Precision', lambda y_t, y_p: precision_score(y_t, y_p, zero_division=0)),
        ('Recall', lambda y_t, y_p: recall_score(y_t, y_p, zero_division=0)),
        ('F1-Score', lambda y_t, y_p: f1_score(y_t, y_p, zero_division=0))
    ]
    
    for metric_name, metric_func in metrics:
        anomaly_score = metric_func(y_true_binary, anomaly_pred_binary)
        classifier_score = metric_func(y_true_binary, classifier_pred_binary)
        
        print(f"{metric_name:<25} {anomaly_score:>20.3f} {classifier_score:>20.3f}")
    
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print("\nIsolation Forest (Unsupervised):")
    print("  + No labeled data required")
    print("  + Detects unknown attack patterns")
    print("  + Fast training and inference")
    print("  - Cannot identify specific attack types")
    print("  - Binary output only (anomaly/normal)")
    
    print("\nRandom Forest (Supervised):")
    print("  + Identifies specific attack types")
    print("  + Higher accuracy with labeled data")
    print("  + Provides confidence scores per class")
    print("  - Requires labeled training data")
    print("  - May miss novel attack patterns")
    
    print("\nRecommendation:")
    print("  Use BOTH models in production:")
    print("  1. Isolation Forest for initial anomaly detection")
    print("  2. Random Forest to classify detected anomalies")
    print("  3. This catches both known and unknown threats")
    print("="*70 + "\n")


def save_training_report(
    output_dir: str,
    anomaly_results: Dict,
    classifier_results: Dict
) -> None:
    """
    Save training report to JSON file.
    
    Args:
        output_dir: Output directory
        anomaly_results: Isolation Forest results
        classifier_results: Random Forest results
    """
    report = {
        'timestamp': datetime.now().isoformat(),
        'models': {
            'isolation_forest': anomaly_results,
            'random_forest': classifier_results
        }
    }
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    report_file = output_path / f'training_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Training report saved to {report_file}")


def main():
    """
    Main training workflow.
    """
    parser = argparse.ArgumentParser(description='Train CloudGuard-AI models')
    parser.add_argument('--events', type=str, default='data/labeled/labeled_events.json',
                       help='Path to labeled events file')
    parser.add_argument('--labels', type=str, default='data/labeled/labels.json',
                       help='Path to labels file')
    parser.add_argument('--output', type=str, default='models/saved_models',
                       help='Output directory for models')
    parser.add_argument('--report-dir', type=str, default='reports',
                       help='Directory for training reports')
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("CLOUDGUARD-AI MODEL TRAINING")
    print("="*70)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    # Check if labeled data exists
    if not Path(args.events).exists():
        logger.error(f"Labeled dataset not found at {args.events}")
        logger.error("Please generate labeled data first:")
        logger.error("  python scripts/generate_labeled_data.py")
        return
    
    try:
        # Load data
        df, labels_data = load_labeled_dataset(args.events, args.labels)
        
        # Prepare features
        df_features, feature_engineer = prepare_features(df)
        
        # Train Isolation Forest
        anomaly_path = Path(args.output) / 'isolation_forest.pkl'
        anomaly_results, anomaly_detector = train_anomaly_detector(
            df_features, feature_engineer, str(anomaly_path)
        )
        
        # Train Random Forest
        classifier_path = Path(args.output) / 'threat_classifier.pkl'
        classifier_results, threat_classifier = train_threat_classifier(
            df_features, labels_data, feature_engineer, str(classifier_path)
        )
        
        # Compare models
        compare_models(
            anomaly_results, classifier_results,
            df_features, labels_data,
            anomaly_detector, threat_classifier
        )
        
        # Save training report
        save_training_report(args.report_dir, anomaly_results, classifier_results)
        
        print("\n" + "="*70)
        print("TRAINING COMPLETE!")
        print("="*70)
        print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\nModels saved to: {args.output}")
        print(f"  - {anomaly_path}")
        print(f"  - {classifier_path}")
        print("="*70 + "\n")
        
    except Exception as e:
        logger.error(f"Training failed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
