"""
Data Preprocessing Module
Cleans and validates CloudTrail data before feature engineering.
"""

import logging
import pandas as pd
import numpy as np
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class DataPreprocessor:
    """
    Handles cleaning and preprocessing of CloudTrail data.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize data preprocessor.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean CloudTrail DataFrame.
        
        Args:
            df: Raw CloudTrail DataFrame
            
        Returns:
            Cleaned DataFrame
        """
        logger.info(f"Cleaning data. Initial shape: {df.shape}")
        
        # Create a copy to avoid modifying original
        df_clean = df.copy()
        
        # Remove completely empty rows
        df_clean = df_clean.dropna(how='all')
        
        # Remove duplicate events
        if 'eventID' in df_clean.columns:
            initial_len = len(df_clean)
            df_clean = df_clean.drop_duplicates(subset=['eventID'])
            removed = initial_len - len(df_clean)
            if removed > 0:
                logger.info(f"Removed {removed} duplicate events")
        
        # Fill missing values
        df_clean = self._handle_missing_values(df_clean)
        
        # Standardize data types
        df_clean = self._standardize_types(df_clean)
        
        logger.info(f"Cleaning complete. Final shape: {df_clean.shape}")
        
        return df_clean
    
    def _handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Handle missing values in the DataFrame.
        
        Args:
            df: DataFrame with potential missing values
            
        Returns:
            DataFrame with handled missing values
        """
        # Fill missing error codes with 'None'
        if 'errorCode' in df.columns:
            df['errorCode'] = df['errorCode'].fillna('None')
        
        # Fill missing error messages
        if 'errorMessage' in df.columns:
            df['errorMessage'] = df['errorMessage'].fillna('None')
        
        # Fill missing user names
        if 'userName' in df.columns:
            df['userName'] = df['userName'].fillna('Unknown')
        
        # Fill missing MFA status
        if 'mfaAuthenticated' in df.columns:
            df['mfaAuthenticated'] = df['mfaAuthenticated'].fillna('false')
        
        # Fill missing readOnly flag
        if 'readOnly' in df.columns:
            df['readOnly'] = df['readOnly'].fillna(True)
        
        return df
    
    def _standardize_types(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Standardize data types for consistency.
        
        Args:
            df: DataFrame to standardize
            
        Returns:
            DataFrame with standardized types
        """
        # Convert eventTime to datetime if not already
        if 'eventTime' in df.columns and df['eventTime'].dtype != 'datetime64[ns]':
            df['eventTime'] = pd.to_datetime(df['eventTime'], errors='coerce')
        
        # Convert boolean columns
        bool_columns = ['readOnly']
        for col in bool_columns:
            if col in df.columns:
                df[col] = df[col].astype(bool)
        
        # Ensure mfaAuthenticated is boolean
        if 'mfaAuthenticated' in df.columns:
            df['mfaAuthenticated'] = df['mfaAuthenticated'].map({
                'true': True,
                'True': True,
                True: True,
                'false': False,
                'False': False,
                False: False
            }).fillna(False)
        
        return df
    
    def filter_events(
        self, 
        df: pd.DataFrame,
        event_names: Optional[List[str]] = None,
        start_time: Optional[pd.Timestamp] = None,
        end_time: Optional[pd.Timestamp] = None,
        users: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """
        Filter events based on criteria.
        
        Args:
            df: DataFrame to filter
            event_names: List of event names to include
            start_time: Start time for filtering
            end_time: End time for filtering
            users: List of usernames to include
            
        Returns:
            Filtered DataFrame
        """
        df_filtered = df.copy()
        
        # Filter by event names
        if event_names:
            df_filtered = df_filtered[df_filtered['eventName'].isin(event_names)]
            logger.info(f"Filtered to {len(df_filtered)} events by event names")
        
        # Filter by time range
        if 'eventTime' in df_filtered.columns:
            if start_time:
                df_filtered = df_filtered[df_filtered['eventTime'] >= start_time]
            if end_time:
                df_filtered = df_filtered[df_filtered['eventTime'] <= end_time]
            logger.info(f"Filtered to {len(df_filtered)} events by time range")
        
        # Filter by users
        if users and 'userName' in df_filtered.columns:
            df_filtered = df_filtered[df_filtered['userName'].isin(users)]
            logger.info(f"Filtered to {len(df_filtered)} events by users")
        
        return df_filtered
    
    def validate_data(self, df: pd.DataFrame) -> bool:
        """
        Validate that DataFrame has required columns and data quality.
        
        Args:
            df: DataFrame to validate
            
        Returns:
            True if valid, raises ValueError otherwise
        """
        required_columns = ['eventTime', 'eventName', 'eventSource']
        
        # Check for required columns
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise ValueError(f"Missing required columns: {missing_columns}")
        
        # Check for empty DataFrame
        if len(df) == 0:
            raise ValueError("DataFrame is empty")
        
        # Check for valid timestamps
        if 'eventTime' in df.columns:
            if df['eventTime'].isnull().any():
                logger.warning("Some events have null timestamps")
        
        logger.info("Data validation passed")
        return True
    
    def get_data_summary(self, df: pd.DataFrame) -> Dict:
        """
        Get summary statistics about the DataFrame.
        
        Args:
            df: DataFrame to summarize
            
        Returns:
            Dictionary with summary statistics
        """
        summary = {
            'total_events': len(df),
            'unique_users': df['userName'].nunique() if 'userName' in df.columns else 0,
            'unique_event_types': df['eventName'].nunique() if 'eventName' in df.columns else 0,
            'unique_services': df['eventSource'].nunique() if 'eventSource' in df.columns else 0,
            'date_range': {
                'start': df['eventTime'].min() if 'eventTime' in df.columns else None,
                'end': df['eventTime'].max() if 'eventTime' in df.columns else None
            },
            'error_rate': (df['errorCode'] != 'None').sum() / len(df) if 'errorCode' in df.columns else 0,
            'mfa_usage_rate': df['mfaAuthenticated'].sum() / len(df) if 'mfaAuthenticated' in df.columns else 0
        }
        
        return summary


def main():
    """
    Example usage of data preprocessing.
    """
    from data_ingestion import CloudTrailIngestion
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Load sample data
    ingester = CloudTrailIngestion()
    events = ingester.load_sample_data()
    df = ingester.events_to_dataframe(events)
    
    # Preprocess
    preprocessor = DataPreprocessor()
    df_clean = preprocessor.clean_data(df)
    
    # Validate
    preprocessor.validate_data(df_clean)
    
    # Get summary
    summary = preprocessor.get_data_summary(df_clean)
    print("\nData Summary:")
    for key, value in summary.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()