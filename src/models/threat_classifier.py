"""
Threat Classifier Module
Random Forest classifier for identifying specific attack types in CloudTrail logs.

Attack Types:
- 0: normal
- 1: privilege_escalation
- 2: data_exfiltration
- 3: reconnaissance
- 4: credential_compromise
"""

import logging
import pickle
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)
import json

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatClassifier:
    """
    Random Forest classifier for identifying specific attack types.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize threat classifier.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.model = None
        self.feature_names = None
        self.is_trained = False
        
        # Attack type mapping
        self.attack_types = {
            0: 'normal',
            1: 'privilege_escalation',
            2: 'data_exfiltration',
            3: 'reconnaissance',
            4: 'credential_compromise'
        }
        
        # Initialize model with config or defaults
        model_config = self.config.get('random_forest', {})
        self.model = RandomForestClassifier(
            n_estimators=model_config.get('n_estimators', 200),
            max_depth=model_config.get('max_depth', 20),
            min_samples_split=model_config.get('min_samples_split', 10),
            min_samples_leaf=model_config.get('min_samples_leaf', 4),
            max_features='sqrt',
            random_state=model_config.get('random_state', 42),
            class_weight='balanced',  # Handle class imbalance
            n_jobs=-1  # Use all CPU cores
        )
        
        logger.info("Threat classifier initialized")
    
    def train(
        self,
        X: pd.DataFrame,
        y: np.ndarray,
        feature_cols: List[str],
        validation_split: float = 0.2
    ) -> Dict:
        """
        Train the Random Forest classifier.
        
        Args:
            X: DataFrame with features
            y: Labels (0=normal, 1=privesc, 2=exfil, 3=recon, 4=cred)
            feature_cols: List of feature column names
            validation_split: Fraction of data for validation
            
        Returns:
            Dictionary with training metrics
        """
        # Filter to available features
        available_features = [col for col in feature_cols if col in X.columns]
        if not available_features:
            raise ValueError("No valid features found in dataset")
        
        self.feature_names = available_features
        X_train = X[self.feature_names].fillna(0)
        
        logger.info(f"Training Random Forest on {len(X_train)} samples with {len(self.feature_names)} features")
        logger.info(f"Class distribution: {np.bincount(y)}")
        
        # Split data
        X_train_split, X_val, y_train_split, y_val = train_test_split(
            X_train, y, test_size=validation_split, random_state=42, stratify=y
        )
        
        # Train model
        self.model.fit(X_train_split, y_train_split)
        self.is_trained = True
        
        logger.info("Training complete")
        
        # Evaluate on validation set
        val_metrics = self.evaluate(X_val, y_val)
        
        # Cross-validation scores
        cv_scores = cross_val_score(
            self.model, X_train, y, cv=5, scoring='f1_macro'
        )
        
        training_metrics = {
            'validation_metrics': val_metrics,
            'cv_f1_mean': cv_scores.mean(),
            'cv_f1_std': cv_scores.std(),
            'feature_importances': self.get_feature_importance(),
            'n_samples_train': len(X_train_split),
            'n_samples_val': len(X_val),
            'n_features': len(self.feature_names)
        }
        
        logger.info(f"Validation Accuracy: {val_metrics['accuracy']:.3f}")
        logger.info(f"Validation F1 (macro): {val_metrics['f1_macro']:.3f}")
        logger.info(f"CV F1 Score: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")
        
        return training_metrics
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict attack types.
        
        Args:
            X: DataFrame with features
            
        Returns:
            Array of predicted labels
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")
        
        X_pred = X[self.feature_names].fillna(0)
        predictions = self.model.predict(X_pred)
        
        return predictions
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """
        Get prediction probabilities for each class.
        
        Args:
            X: DataFrame with features
            
        Returns:
            Array of shape (n_samples, n_classes) with probabilities
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")
        
        X_pred = X[self.feature_names].fillna(0)
        probabilities = self.model.predict_proba(X_pred)
        
        return probabilities
    
    def classify_threats(
        self,
        X: pd.DataFrame,
        confidence_threshold: float = 0.7
    ) -> pd.DataFrame:
        """
        Classify threats with confidence scores.
        
        Args:
            X: DataFrame with features
            confidence_threshold: Minimum confidence for classification
            
        Returns:
            DataFrame with predictions and confidence scores
        """
        predictions = self.predict(X)
        probabilities = self.predict_proba(X)
        
        # Get confidence (max probability for predicted class)
        confidence = probabilities.max(axis=1)
        
        # Create results DataFrame
        results = X.copy()
        results['predicted_label'] = predictions
        results['predicted_type'] = [self.attack_types[pred] for pred in predictions]
        results['confidence'] = confidence
        results['high_confidence'] = confidence >= confidence_threshold
        
        # Add probabilities for each class
        for label, attack_type in self.attack_types.items():
            results[f'prob_{attack_type}'] = probabilities[:, label]
        
        return results
    
    def evaluate(self, X: pd.DataFrame, y_true: np.ndarray) -> Dict:
        """
        Evaluate model performance.
        
        Args:
            X: DataFrame with features
            y_true: True labels
            
        Returns:
            Dictionary with evaluation metrics
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")
        
        X_eval = X[self.feature_names].fillna(0)
        y_pred = self.model.predict(X_eval)
        y_proba = self.model.predict_proba(X_eval)
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision_macro': precision_score(y_true, y_pred, average='macro', zero_division=0),
            'recall_macro': recall_score(y_true, y_pred, average='macro', zero_division=0),
            'f1_macro': f1_score(y_true, y_pred, average='macro', zero_division=0),
            'precision_weighted': precision_score(y_true, y_pred, average='weighted', zero_division=0),
            'recall_weighted': recall_score(y_true, y_pred, average='weighted', zero_division=0),
            'f1_weighted': f1_score(y_true, y_pred, average='weighted', zero_division=0),
        }
        
        # Per-class metrics
        class_report = classification_report(
            y_true, y_pred,
            target_names=list(self.attack_types.values()),
            output_dict=True,
            zero_division=0
        )
        metrics['class_report'] = class_report
        
        # Confusion matrix
        conf_matrix = confusion_matrix(y_true, y_pred)
        metrics['confusion_matrix'] = conf_matrix.tolist()
        
        # ROC AUC (one-vs-rest for multiclass)
        try:
            roc_auc = roc_auc_score(y_true, y_proba, multi_class='ovr', average='macro')
            metrics['roc_auc_macro'] = roc_auc
        except Exception as e:
            logger.warning(f"Could not calculate ROC AUC: {e}")
            metrics['roc_auc_macro'] = None
        
        logger.info(f"Evaluation complete - Accuracy: {metrics['accuracy']:.3f}, "
                   f"F1 (macro): {metrics['f1_macro']:.3f}")
        
        return metrics
    
    def get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importance scores.
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")
        
        importances = self.model.feature_importances_
        importance_dict = {
            feature: float(importance)
            for feature, importance in zip(self.feature_names, importances)
        }
        
        # Sort by importance
        importance_dict = dict(
            sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
        )
        
        return importance_dict
    
    def save_model(self, filepath: str) -> None:
        """
        Save trained model to file.
        
        Args:
            filepath: Path to save model
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Cannot save untrained model.")
        
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        model_data = {
            'model': self.model,
            'feature_names': self.feature_names,
            'attack_types': self.attack_types,
            'config': self.config
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str) -> None:
        """
        Load trained model from file.
        
        Args:
            filepath: Path to model file
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.model = model_data['model']
        self.feature_names = model_data['feature_names']
        self.attack_types = model_data.get('attack_types', self.attack_types)
        self.config = model_data.get('config', {})
        self.is_trained = True
        
        logger.info(f"Model loaded from {filepath}")
    
    def print_classification_report(self, X: pd.DataFrame, y_true: np.ndarray) -> None:
        """
        Print detailed classification report.
        
        Args:
            X: DataFrame with features
            y_true: True labels
        """
        metrics = self.evaluate(X, y_true)
        
        print("\n" + "="*70)
        print("CLASSIFICATION REPORT")
        print("="*70)
        
        print(f"\nOverall Metrics:")
        print(f"  Accuracy:          {metrics['accuracy']:.3f}")
        print(f"  Precision (macro): {metrics['precision_macro']:.3f}")
        print(f"  Recall (macro):    {metrics['recall_macro']:.3f}")
        print(f"  F1-Score (macro):  {metrics['f1_macro']:.3f}")
        
        if metrics.get('roc_auc_macro'):
            print(f"  ROC AUC (macro):   {metrics['roc_auc_macro']:.3f}")
        
        print(f"\nPer-Class Metrics:")
        print(f"{'Class':<25} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Support':>10}")
        print("-"*70)
        
        for attack_type in self.attack_types.values():
            if attack_type in metrics['class_report']:
                class_metrics = metrics['class_report'][attack_type]
                print(f"{attack_type:<25} "
                      f"{class_metrics['precision']:>10.3f} "
                      f"{class_metrics['recall']:>10.3f} "
                      f"{class_metrics['f1-score']:>10.3f} "
                      f"{int(class_metrics['support']):>10}")
        
        print("\nConfusion Matrix:")
        print("Rows: True labels, Columns: Predicted labels")
        conf_matrix = np.array(metrics['confusion_matrix'])
        
        # Print header
        print(f"{'':>25}", end='')
        for attack_type in self.attack_types.values():
            print(f"{attack_type[:10]:>12}", end='')
        print()
        
        # Print matrix
        for i, attack_type in enumerate(self.attack_types.values()):
            print(f"{attack_type:<25}", end='')
            for j in range(len(self.attack_types)):
                print(f"{conf_matrix[i][j]:>12}", end='')
            print()
        
        print("="*70 + "\n")


def main():
    """
    Example usage of threat classifier.
    """
    from data.data_ingestion import CloudTrailIngestion
    from data.data_preprocessing import DataPreprocessor
    from data.feature_engineering import FeatureEngineer
    import json
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    print("="*70)
    print("THREAT CLASSIFIER - EXAMPLE USAGE")
    print("="*70)
    
    # Load labeled data
    print("\n1. Loading labeled dataset...")
    events_file = 'data/labeled/labeled_events.json'
    labels_file = 'data/labeled/labels.json'
    
    # Check if files exist
    if not Path(events_file).exists():
        print(f"\nERROR: Labeled dataset not found at {events_file}")
        print("Please generate labeled data first:")
        print("  python scripts/generate_labeled_data.py")
        return
    
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
    
    # Preprocess
    print("2. Preprocessing data...")
    preprocessor = DataPreprocessor()
    df_clean = preprocessor.clean_data(df)
    
    # Extract features
    print("3. Extracting features...")
    engineer = FeatureEngineer()
    df_features = engineer.extract_features(df_clean)
    
    # Get labels
    y = np.array([
        labels_data['event_labels'][event_id]['label']
        for event_id in df_features['eventID']
    ])
    
    # Get feature columns
    feature_cols = engineer.get_feature_columns()
    
    # Train classifier
    print("4. Training Random Forest classifier...")
    classifier = ThreatClassifier()
    training_metrics = classifier.train(df_features, y, feature_cols, validation_split=0.2)
    
    # Print results
    print("\n" + "="*70)
    print("TRAINING RESULTS")
    print("="*70)
    print(f"\nCross-Validation F1: {training_metrics['cv_f1_mean']:.3f} "
          f"(+/- {training_metrics['cv_f1_std']:.3f})")
    
    print(f"\nTop 10 Important Features:")
    for i, (feature, importance) in enumerate(list(training_metrics['feature_importances'].items())[:10], 1):
        print(f"  {i:2}. {feature:<30} {importance:.4f}")
    
    # Classify threats on full dataset
    print("\n5. Classifying threats...")
    results = classifier.classify_threats(df_features, confidence_threshold=0.7)
    
    # Show high-confidence threats
    threats = results[
        (results['predicted_type'] != 'normal') & 
        (results['high_confidence'])
    ]
    
    print(f"\nDetected {len(threats)} high-confidence threats:")
    print(threats[['eventName', 'userName', 'predicted_type', 'confidence']].head(10))
    
    # Save model
    print("\n6. Saving model...")
    model_path = 'models/saved_models/threat_classifier.pkl'
    classifier.save_model(model_path)
    print(f"Model saved to {model_path}")
    
    print("\n" + "="*70)
    print("Example complete!")
    print("="*70)


if __name__ == "__main__":
    main()
