"""
Generate Sample CloudTrail Data
Creates synthetic CloudTrail logs for development and testing.
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
import argparse


def generate_normal_event(timestamp, user_pool, service_pool):
    """Generate a normal CloudTrail event."""
    user = random.choice(user_pool)
    service = random.choice(service_pool)
    
    # Normal read operations
    read_events = {
        's3.amazonaws.com': ['GetObject', 'ListBucket', 'HeadObject'],
        'ec2.amazonaws.com': ['DescribeInstances', 'DescribeVolumes'],
        'rds.amazonaws.com': ['DescribeDBInstances'],
        'iam.amazonaws.com': ['GetUser', 'ListUsers'],
        'lambda.amazonaws.com': ['ListFunctions', 'GetFunction']
    }
    
    event_name = random.choice(read_events.get(service, ['DescribeInstances']))
    
    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": f"AIDAI{random.randint(10000, 99999)}",
            "arn": f"arn:aws:iam::123456789012:user/{user}",
            "accountId": "123456789012",
            "accessKeyId": f"AKIAI{random.randint(10000, 99999)}",
            "userName": user,
            "sessionContext": {
                "attributes": {
                    "mfaAuthenticated": str(random.choice([True, True, False])).lower(),
                    "creationDate": timestamp.isoformat() + "Z"
                }
            }
        },
        "eventTime": timestamp.isoformat() + "Z",
        "eventSource": service,
        "eventName": event_name,
        "awsRegion": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
        "sourceIPAddress": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "userAgent": f"aws-cli/{random.choice(['2.13.0', '2.14.0'])} Python/3.11.{random.randint(0,5)}",
        "requestParameters": None,
        "responseElements": None,
        "requestID": f"req-{random.randint(100000, 999999)}",
        "eventID": f"event-{random.randint(100000, 999999)}-{random.randint(1000, 9999)}",
        "readOnly": True,
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012"
    }
    
    return event


def generate_suspicious_event(timestamp, user_pool):
    """Generate a suspicious CloudTrail event."""
    event_type = random.choice([
        'privilege_escalation',
        'unusual_location',
        'failed_auth',
        'data_access'
    ])
    
    user = random.choice(user_pool)
    
    if event_type == 'privilege_escalation':
        # Privilege escalation attempt
        event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDAI{random.randint(10000, 99999)}",
                "arn": f"arn:aws:iam::123456789012:user/{user}",
                "accountId": "123456789012",
                "userName": user
            },
            "eventTime": timestamp.isoformat() + "Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": random.choice(['AttachUserPolicy', 'PutUserPolicy', 'AddUserToGroup']),
            "awsRegion": "us-east-1",
            "sourceIPAddress": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "userAgent": "aws-cli/2.13.0",
            "requestParameters": {
                "userName": user,
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            "errorCode": "AccessDenied",
            "errorMessage": "User is not authorized to perform: iam:AttachUserPolicy",
            "requestID": f"req-{random.randint(100000, 999999)}",
            "eventID": f"event-suspicious-{random.randint(100000, 999999)}",
            "readOnly": False,
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012"
        }
    
    elif event_type == 'unusual_location':
        # Access from unusual location
        event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDAI{random.randint(10000, 99999)}",
                "arn": f"arn:aws:iam::123456789012:user/{user}",
                "accountId": "123456789012",
                "userName": user,
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "false"
                    }
                }
            },
            "eventTime": timestamp.isoformat() + "Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": random.choice([
                "185.220.100.240",  # Tor exit node
                "103.253.145.12",   # Unusual country
                "45.95.168.110"     # Suspicious IP
            ]),
            "userAgent": "Mozilla/5.0",
            "responseElements": {"ConsoleLogin": "Success"},
            "requestID": f"req-{random.randint(100000, 999999)}",
            "eventID": f"event-suspicious-{random.randint(100000, 999999)}",
            "readOnly": False,
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "123456789012"
        }
    
    elif event_type == 'failed_auth':
        # Multiple failed authentication attempts
        event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "arn": f"arn:aws:iam::123456789012:user/{user}",
                "accountId": "123456789012",
                "userName": user
            },
            "eventTime": timestamp.isoformat() + "Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "userAgent": "Mozilla/5.0",
            "errorCode": "Failed authentication",
            "errorMessage": "Invalid username or password",
            "requestID": f"req-{random.randint(100000, 999999)}",
            "eventID": f"event-suspicious-{random.randint(100000, 999999)}",
            "readOnly": False,
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "123456789012"
        }
    
    else:  # data_access
        # Unusual data access
        event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDAI{random.randint(10000, 99999)}",
                "arn": f"arn:aws:iam::123456789012:user/{user}",
                "accountId": "123456789012",
                "userName": user
            },
            "eventTime": timestamp.isoformat() + "Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "awsRegion": "us-east-1",
            "sourceIPAddress": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "userAgent": "aws-cli/2.13.0",
            "requestParameters": {
                "bucketName": "sensitive-data-bucket",
                "key": random.choice([
                    "customer-pii/ssn-data.csv",
                    "financial/credit-cards.xlsx",
                    "secrets/api-keys.txt"
                ])
            },
            "requestID": f"req-{random.randint(100000, 999999)}",
            "eventID": f"event-suspicious-{random.randint(100000, 999999)}",
            "readOnly": True,
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012"
        }
    
    return event


def generate_sample_data(
    num_events=1000,
    num_anomalies=50,
    output_dir='data/sample',
    filename='sample_cloudtrail_logs.json'
):
    """
    Generate sample CloudTrail logs.
    
    Args:
        num_events: Number of normal events to generate
        num_anomalies: Number of suspicious events to generate
        output_dir: Output directory
        filename: Output filename
    """
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # User and service pools
    user_pool = ['alice', 'bob', 'charlie', 'david', 'emma', 'frank']
    service_pool = [
        's3.amazonaws.com',
        'ec2.amazonaws.com',
        'rds.amazonaws.com',
        'iam.amazonaws.com',
        'lambda.amazonaws.com'
    ]
    
    # Generate events
    events = []
    start_time = datetime.now() - timedelta(days=7)
    
    print(f"Generating {num_events} normal events...")
    for i in range(num_events):
        # Random timestamp within last 7 days
        timestamp = start_time + timedelta(
            minutes=random.randint(0, 7*24*60)
        )
        event = generate_normal_event(timestamp, user_pool, service_pool)
        events.append(event)
    
    print(f"Generating {num_anomalies} suspicious events...")
    for i in range(num_anomalies):
        timestamp = start_time + timedelta(
            minutes=random.randint(0, 7*24*60)
        )
        event = generate_suspicious_event(timestamp, user_pool)
        events.append(event)
    
    # Sort by timestamp
    events.sort(key=lambda x: x['eventTime'])
    
    # Create CloudTrail log structure
    cloudtrail_data = {
        "Records": events
    }
    
    # Save to file
    output_file = output_path / filename
    with open(output_file, 'w') as f:
        json.dump(cloudtrail_data, f, indent=2)
    
    print(f"\nGenerated {len(events)} total events")
    print(f"Saved to: {output_file}")
    print(f"Normal events: {num_events}")
    print(f"Suspicious events: {num_anomalies}")
    print(f"Anomaly rate: {num_anomalies/len(events)*100:.1f}%")


def main():
    parser = argparse.ArgumentParser(description='Generate sample CloudTrail logs')
    parser.add_argument('--num-events', type=int, default=1000,
                       help='Number of normal events to generate')
    parser.add_argument('--num-anomalies', type=int, default=50,
                       help='Number of suspicious events to generate')
    parser.add_argument('--output', type=str, default='data/sample',
                       help='Output directory')
    parser.add_argument('--filename', type=str, default='sample_cloudtrail_logs.json',
                       help='Output filename')
    
    args = parser.parse_args()
    
    generate_sample_data(
        num_events=args.num_events,
        num_anomalies=args.num_anomalies,
        output_dir=args.output,
        filename=args.filename
    )


if __name__ == "__main__":
    main()