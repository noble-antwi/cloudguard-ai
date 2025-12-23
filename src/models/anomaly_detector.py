"""
Anomaly Detection Module
Uses Isolation Forest to detect anomalous CloudTrail events.
"""

import logging
import pickle
from pathlib import Path
from typing import Dict, Optional, Tuple
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Detects anomalous behavior in CloudTrail logs using Isolation Forest.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize anomaly detector.
        
        Args:
            config: Configuration dictionary with model parameters
        """
        self.config = config or {}
        model_config = self.config.get('model', {}).get('isolation_forest', {})
        
        # Initialize Isolation Forest
        self.model = IsolationForest(
            n_estimators=model_config.get('n_estimators', 100),
            contamination=model_config.get('contamination', 0.1),
            max_samples=model_config.get('max_samples', 256),
            random_state=model_config.get('random_state', 42),
            n_jobs=-1
        )
        
        self.is_trained = False
        self.feature_names = []
        
        logger.info("Anomaly detector initialized")
    
    def train(self, X: pd.DataFrame, feature_cols: Optional[list] = None) -> None:
        """
        Train the Isolation Forest model.
        
        Args:
            X: DataFrame with features
            feature_cols: List of feature column names to use
        """
        if feature_cols:
            self.feature_names = feature_cols
            X_train = X[feature_cols]
        else:
            self.feature_names = list(X.columns)
            X_train = X
        
        logger.info(f"Training Isolation Forest on {len(X_train)} samples with {len(self.feature_names)} features")
        
        # Handle any missing values
        X_train = X_train.fillna(0)
        
        # Train the model
        self.model.fit(X_train)
        self.is_trained = True
        
        logger.info("Training complete")
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict anomalies in new data.
        
        Args:
            X: DataFrame with features
            
        Returns:
            Array of predictions (-1 for anomaly, 1 for normal)
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")
        
        X_pred = X[self.feature_names].fillna(0)
        predictions = self.model.predict(X_pred)
        
        return predictions
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """
        Get anomaly scores for samples.
        
        Args:
            X: DataFrame with features
            
        Returns:
            Array of anomaly scores (lower = more anomalous)
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")
        
        X_pred = X[self.feature_names].fillna(0)
        
        # Get anomaly scores (lower means more anomalous)
        scores = self.model.score_samples(X_pred)
        
        # Convert to probability-like scores (0-1, higher = more anomalous)
        # Normalize scores to 0-1 range
        min_score = scores.min()
        max_score = scores.max()
        
        if max_score - min_score == 0:
            normalized_scores = np.zeros_like(scores)
        else:
            normalized_scores = 1 - (scores - min_score) / (max_score - min_score)
        
        return normalized_scores
    
    def detect_anomalies(
        self, 
        X: pd.DataFrame, 
        threshold: float = 0.7
    ) -> Tuple[pd.DataFrame, np.ndarray]:
        """
        Detect anomalies and return results with scores.
        
        Args:
            X: DataFrame with features
            threshold: Anomaly score threshold (0-1)
            
        Returns:
            Tuple of (anomalous samples DataFrame, anomaly scores)
        """
        # Get predictions and scores
        predictions = self.predict(X)
        scores = self.predict_proba(X)
        
        # Create result DataFrame
        results = X.copy()
        results['anomaly_prediction'] = predictions
        results['anomaly_score'] = scores
        results['is_anomaly'] = (predictions == -1) & (scores >= threshold)
        
        # Filter to anomalies
        anomalies = results[results['is_anomaly']]
        
        logger.info(f"Detected {len(anomalies)} anomalies out of {len(X)} samples")
        
        return anomalies, scores
    
    def evaluate(
        self, 
        X: pd.DataFrame, 
        y_true: np.ndarray
    ) -> Dict:
        """
        Evaluate model performance on labeled data.
        
        Args:
            X: DataFrame with features
            y_true: True labels (1 for normal, -1 for anomaly)
            
        Returns:
            Dictionary with evaluation metrics
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")
        
        y_pred = self.predict(X)
        scores = self.predict_proba(X)
        
        # Calculate metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        # Convert labels: -1 (anomaly) -> 1, 1 (normal) -> 0 for metrics
        y_true_binary = (y_true == -1).astype(int)
        y_pred_binary = (y_pred == -1).astype(int)
        
        metrics = {
            'accuracy': accuracy_score(y_true_binary, y_pred_binary),
            'precision': precision_score(y_true_binary, y_pred_binary, zero_division=0),
            'recall': recall_score(y_true_binary, y_pred_binary, zero_division=0),
            'f1_score': f1_score(y_true_binary, y_pred_binary, zero_division=0),
            'confusion_matrix': confusion_matrix(y_true_binary, y_pred_binary).tolist()
        }
        
        logger.info(f"Model evaluation - Accuracy: {metrics['accuracy']:.3f}, "
                   f"Precision: {metrics['precision']:.3f}, "
                   f"Recall: {metrics['recall']:.3f}")
        
        return metrics
    
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
        self.config = model_data.get('config', {})
        self.is_trained = True
        
        logger.info(f"Model loaded from {filepath}")


def main():
    """
    Example usage of anomaly detector.
    """
    from data.data_ingestion import CloudTrailIngestion
    from data.data_preprocessing import DataPreprocessor
    from data.feature_engineering import FeatureEngineer
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Load and prepare data
    ingester = CloudTrailIngestion()
    events = ingester.load_sample_data()
    df = ingester.events_to_dataframe(events)
    
    preprocessor = DataPreprocessor()
    df_clean = preprocessor.clean_data(df)
    
    engineer = FeatureEngineer()
    df_features = engineer.extract_features(df_clean)
    
    # Get feature columns
    feature_cols = engineer.get_feature_columns()
    existing_features = [col for col in feature_cols if col in df_features.columns]
    
    # Train anomaly detector
    detector = AnomalyDetector()
    detector.train(df_features, feature_cols=existing_features)
    
    # Detect anomalies
    anomalies, scores = detector.detect_anomalies(df_features, threshold=0.7)
    
    print(f"\nDetected {len(anomalies)} anomalies")
    if len(anomalies) > 0:
        print("\nTop anomalies:")
        print(anomalies[['eventName', 'userName', 'anomaly_score']].head())


if __name__ == "__main__":
    main()