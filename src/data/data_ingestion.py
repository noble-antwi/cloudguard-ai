"""
Data Ingestion Module
Handles reading and parsing AWS CloudTrail logs from S3 or local files.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
import boto3
from botocore.exceptions import ClientError
import pandas as pd
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class CloudTrailIngestion:
    """
    Handles ingestion of AWS CloudTrail logs from various sources.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize CloudTrail ingestion handler.
        
        Args:
            config: Configuration dictionary with AWS settings
        """
        self.config = config or {}
        self.s3_client = None
        
        # Initialize S3 client if AWS config provided
        if self.config.get('aws'):
            try:
                self.s3_client = boto3.client(
                    's3',
                    region_name=self.config['aws'].get('region', 'us-east-1')
                )
                logger.info("S3 client initialized successfully")
            except Exception as e:
                logger.warning(f"Could not initialize S3 client: {e}")
    
    def load_from_file(self, file_path: str) -> List[Dict]:
        """
        Load CloudTrail logs from a local JSON file.
        
        Args:
            file_path: Path to the CloudTrail JSON file
            
        Returns:
            List of CloudTrail event dictionaries
        """
        try:
            file_path = Path(file_path)
            logger.info(f"Loading CloudTrail logs from {file_path}")
            
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # CloudTrail logs have a 'Records' key
            events = data.get('Records', [])
            logger.info(f"Loaded {len(events)} events from {file_path}")
            
            return events
            
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading file {file_path}: {e}")
            raise
    
    def load_from_s3(
        self, 
        bucket: str, 
        prefix: str = '', 
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict]:
        """
        Load CloudTrail logs from S3 bucket.
        
        Args:
            bucket: S3 bucket name
            prefix: S3 key prefix (folder path)
            start_date: Optional start date for filtering
            end_date: Optional end date for filtering
            
        Returns:
            List of CloudTrail event dictionaries
        """
        if not self.s3_client:
            raise RuntimeError("S3 client not initialized. Check AWS credentials.")
        
        logger.info(f"Loading CloudTrail logs from s3://{bucket}/{prefix}")
        
        all_events = []
        
        try:
            # List objects in the bucket
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=bucket, Prefix=prefix)
            
            for page in pages:
                if 'Contents' not in page:
                    continue
                
                for obj in page['Contents']:
                    key = obj['Key']
                    
                    # Skip if not a JSON file
                    if not key.endswith('.json.gz') and not key.endswith('.json'):
                        continue
                    
                    # Date filtering (if provided)
                    if start_date or end_date:
                        obj_date = obj['LastModified'].replace(tzinfo=None)
                        if start_date and obj_date < start_date:
                            continue
                        if end_date and obj_date > end_date:
                            continue
                    
                    # Download and parse the file
                    try:
                        response = self.s3_client.get_object(Bucket=bucket, Key=key)
                        content = response['Body'].read()
                        
                        # Handle gzipped files
                        if key.endswith('.gz'):
                            import gzip
                            content = gzip.decompress(content)
                        
                        data = json.loads(content.decode('utf-8'))
                        events = data.get('Records', [])
                        all_events.extend(events)
                        
                        logger.info(f"Loaded {len(events)} events from {key}")
                        
                    except Exception as e:
                        logger.warning(f"Error processing {key}: {e}")
                        continue
            
            logger.info(f"Total events loaded from S3: {len(all_events)}")
            return all_events
            
        except ClientError as e:
            logger.error(f"AWS S3 error: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading from S3: {e}")
            raise
    
    def load_sample_data(self, sample_file: Optional[str] = None) -> List[Dict]:
        """
        Load sample CloudTrail data for testing.
        
        Args:
            sample_file: Optional path to sample data file
            
        Returns:
            List of CloudTrail event dictionaries
        """
        if sample_file:
            return self.load_from_file(sample_file)
        
        # Default sample file location
        default_sample = Path('data/sample/sample_cloudtrail_logs.json')
        
        if default_sample.exists():
            return self.load_from_file(str(default_sample))
        else:
            logger.warning("No sample data file found")
            return []
    
    def events_to_dataframe(self, events: List[Dict]) -> pd.DataFrame:
        """
        Convert CloudTrail events to pandas DataFrame.
        
        Args:
            events: List of CloudTrail event dictionaries
            
        Returns:
            DataFrame with flattened event data
        """
        if not events:
            return pd.DataFrame()
        
        # Flatten nested structures
        flattened_events = []
        
        for event in events:
            flat_event = {
                'eventVersion': event.get('eventVersion'),
                'eventID': event.get('eventID'),
                'eventTime': event.get('eventTime'),
                'eventName': event.get('eventName'),
                'eventSource': event.get('eventSource'),
                'awsRegion': event.get('awsRegion'),
                'sourceIPAddress': event.get('sourceIPAddress'),
                'userAgent': event.get('userAgent'),
                'errorCode': event.get('errorCode'),
                'errorMessage': event.get('errorMessage'),
                'requestID': event.get('requestID'),
                'eventType': event.get('eventType'),
                'readOnly': event.get('readOnly'),
                'recipientAccountId': event.get('recipientAccountId'),
            }
            
            # Extract user identity info
            user_identity = event.get('userIdentity', {})
            flat_event['userType'] = user_identity.get('type')
            flat_event['principalId'] = user_identity.get('principalId')
            flat_event['userName'] = user_identity.get('userName')
            flat_event['accountId'] = user_identity.get('accountId')
            
            # Check for MFA
            session_context = user_identity.get('sessionContext', {})
            attributes = session_context.get('attributes', {})
            flat_event['mfaAuthenticated'] = attributes.get('mfaAuthenticated', 'false')
            
            flattened_events.append(flat_event)
        
        df = pd.DataFrame(flattened_events)
        
        # Convert eventTime to datetime
        if 'eventTime' in df.columns:
            df['eventTime'] = pd.to_datetime(df['eventTime'])
        
        logger.info(f"Created DataFrame with {len(df)} rows and {len(df.columns)} columns")
        
        return df


def main():
    """
    Example usage of CloudTrail ingestion.
    """
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize ingester
    ingester = CloudTrailIngestion()
    
    # Load sample data
    events = ingester.load_sample_data()
    
    if events:
        print(f"Loaded {len(events)} CloudTrail events")
        
        # Convert to DataFrame
        df = ingester.events_to_dataframe(events)
        print(f"\nDataFrame shape: {df.shape}")
        print(f"\nColumns: {list(df.columns)}")
        print(f"\nSample events:")
        print(df[['eventTime', 'eventName', 'userName', 'sourceIPAddress']].head())
    else:
        print("No events loaded")


if __name__ == "__main__":
    main()