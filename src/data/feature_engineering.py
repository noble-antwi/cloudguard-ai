"""
Feature Engineering Module
Extracts meaningful features from CloudTrail events for ML models.
"""

import logging
import pandas as pd
import numpy as np
from typing import Dict, Optional
from datetime import datetime
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """
    Extracts and engineers features from CloudTrail data.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize feature engineer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.scaler = StandardScaler()
        self.feature_names = []
    
    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract all features from CloudTrail DataFrame.
        
        Args:
            df: Cleaned CloudTrail DataFrame
            
        Returns:
            DataFrame with engineered features
        """
        logger.info(f"Extracting features from {len(df)} events")
        
        features_df = df.copy()
        
        # Temporal features
        features_df = self._add_temporal_features(features_df)
        
        # Behavioral features
        features_df = self._add_behavioral_features(features_df)
        
        # Event-specific features
        features_df = self._add_event_features(features_df)
        
        # Geographic features (basic)
        features_df = self._add_geographic_features(features_df)
        
        logger.info(f"Feature extraction complete. Shape: {features_df.shape}")
        
        return features_df
    
    def _add_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add time-based features.
        
        Args:
            df: DataFrame with eventTime column
            
        Returns:
            DataFrame with temporal features added
        """
        if 'eventTime' not in df.columns:
            logger.warning("No eventTime column found")
            return df
        
        # Hour of day (0-23)
        df['hour_of_day'] = df['eventTime'].dt.hour
        
        # Day of week (0-6, Monday=0)
        df['day_of_week'] = df['eventTime'].dt.dayofweek
        
        # Is weekend
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        
        # Is business hours (9 AM - 5 PM)
        df['is_business_hours'] = df['hour_of_day'].between(9, 17).astype(int)
        
        logger.info("Added temporal features")
        
        return df
    
    def _add_behavioral_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add user behavior features.
        
        Args:
            df: DataFrame with user activity
            
        Returns:
            DataFrame with behavioral features
        """
        if 'userName' not in df.columns:
            logger.warning("No userName column found")
            return df
        
        # Sort by user and time
        df = df.sort_values(['userName', 'eventTime'])
        
        # Time since last activity for each user (in minutes)
        df['time_since_last_activity'] = df.groupby('userName')['eventTime'].diff().dt.total_seconds() / 60
        df['time_since_last_activity'] = df['time_since_last_activity'].fillna(0)
        
        # API calls per user per hour (rolling window)
        df['user_api_calls_per_hour'] = df.groupby('userName')['eventName'].transform('count')
        
        # Unique services accessed by user
        df['user_unique_services'] = df.groupby('userName')['eventSource'].transform('nunique')
        
        # Failed API calls for user
        if 'errorCode' in df.columns:
            df['user_failed_calls'] = df.groupby('userName')['errorCode'].transform(
                lambda x: (x != 'None').sum()
            )
        
        logger.info("Added behavioral features")
        
        return df
    
    def _add_event_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add event-specific features.
        
        Args:
            df: DataFrame with event data
            
        Returns:
            DataFrame with event features
        """
        # Is error event
        if 'errorCode' in df.columns:
            df['is_error'] = (df['errorCode'] != 'None').astype(int)
        
        # Is write operation (not readOnly)
        if 'readOnly' in df.columns:
            df['is_write_operation'] = (~df['readOnly']).astype(int)
        
        # MFA used
        if 'mfaAuthenticated' in df.columns:
            df['mfa_used'] = df['mfaAuthenticated'].astype(int)
        
        # Is IAM event (security-sensitive)
        if 'eventSource' in df.columns:
            df['is_iam_event'] = df['eventSource'].str.contains('iam', case=False, na=False).astype(int)
        
        # Is privileged event (potential privilege escalation)
        privileged_events = [
            'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 
            'PutRolePolicy', 'AddUserToGroup', 'CreateAccessKey',
            'CreateUser', 'AssumeRole'
        ]
        if 'eventName' in df.columns:
            df['is_privileged_event'] = df['eventName'].isin(privileged_events).astype(int)
        
        # Is data access event (potential exfiltration)
        data_events = ['GetObject', 'CopyObject', 'DownloadDBSnapshot', 'CreateSnapshot']
        if 'eventName' in df.columns:
            df['is_data_access'] = df['eventName'].isin(data_events).astype(int)
        
        # Is reconnaissance event
        recon_events = ['DescribeInstances', 'ListBuckets', 'DescribeSecurityGroups', 'GetAccountSummary']
        if 'eventName' in df.columns:
            df['is_reconnaissance'] = df['eventName'].isin(recon_events).astype(int)
        
        logger.info("Added event-specific features")
        
        return df
    
    def _add_geographic_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add geography-based features.
        
        Args:
            df: DataFrame with sourceIPAddress
            
        Returns:
            DataFrame with geographic features
        """
        if 'sourceIPAddress' not in df.columns:
            logger.warning("No sourceIPAddress column found")
            return df
        
        # Is AWS internal IP (starts with certain patterns)
        aws_patterns = ['AWS', 'aws', 'cloudfront', 'amazonaws']
        df['is_aws_internal'] = df['sourceIPAddress'].apply(
            lambda x: any(pattern in str(x) for pattern in aws_patterns)
        ).astype(int)
        
        # Unique IPs per user
        df['user_unique_ips'] = df.groupby('userName')['sourceIPAddress'].transform('nunique')
        
        logger.info("Added geographic features")
        
        return df
    
    def get_feature_columns(self) -> list:
        """
        Get list of all feature columns (excluding metadata).
        
        Returns:
            List of feature column names
        """
        feature_cols = [
            # Temporal
            'hour_of_day', 'day_of_week', 'is_weekend', 'is_business_hours',
            # Behavioral
            'time_since_last_activity', 'user_api_calls_per_hour', 
            'user_unique_services', 'user_failed_calls',
            # Event-specific
            'is_error', 'is_write_operation', 'mfa_used', 'is_iam_event',
            'is_privileged_event', 'is_data_access', 'is_reconnaissance',
            # Geographic
            'is_aws_internal', 'user_unique_ips'
        ]
        
        return feature_cols
    
    def scale_features(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        """
        Scale numerical features using StandardScaler.
        
        Args:
            df: DataFrame with features
            fit: Whether to fit the scaler (True for training, False for inference)
            
        Returns:
            DataFrame with scaled features
        """
        feature_cols = self.get_feature_columns()
        
        # Filter to only columns that exist
        existing_cols = [col for col in feature_cols if col in df.columns]
        
        if not existing_cols:
            logger.warning("No feature columns found for scaling")
            return df
        
        df_scaled = df.copy()
        
        if fit:
            df_scaled[existing_cols] = self.scaler.fit_transform(df[existing_cols])
            logger.info(f"Fitted scaler on {len(existing_cols)} features")
        else:
            df_scaled[existing_cols] = self.scaler.transform(df[existing_cols])
            logger.info(f"Transformed {len(existing_cols)} features")
        
        return df_scaled
    
    def get_feature_summary(self, df: pd.DataFrame) -> Dict:
        """
        Get summary statistics of extracted features.
        
        Args:
            df: DataFrame with features
            
        Returns:
            Dictionary with feature statistics
        """
        feature_cols = self.get_feature_columns()
        existing_cols = [col for col in feature_cols if col in df.columns]
        
        summary = {}
        for col in existing_cols:
            summary[col] = {
                'mean': df[col].mean(),
                'std': df[col].std(),
                'min': df[col].min(),
                'max': df[col].max(),
                'missing': df[col].isnull().sum()
            }
        
        return summary


def main():
    """
    Example usage of feature engineering.
    """
    from data_ingestion import CloudTrailIngestion
    from data_preprocessing import DataPreprocessor
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Load and preprocess data
    ingester = CloudTrailIngestion()
    events = ingester.load_sample_data()
    df = ingester.events_to_dataframe(events)
    
    preprocessor = DataPreprocessor()
    df_clean = preprocessor.clean_data(df)
    
    # Extract features
    engineer = FeatureEngineer()
    df_features = engineer.extract_features(df_clean)
    
    # Show feature summary
    print("\nExtracted Features:")
    feature_cols = engineer.get_feature_columns()
    existing_features = [col for col in feature_cols if col in df_features.columns]
    print(f"Total features: {len(existing_features)}")
    print(f"Features: {existing_features}")
    
    # Show sample
    print("\nSample data with features:")
    display_cols = ['eventName', 'userName'] + existing_features[:5]
    display_cols = [col for col in display_cols if col in df_features.columns]
    print(df_features[display_cols].head())


if __name__ == "__main__":
    main()