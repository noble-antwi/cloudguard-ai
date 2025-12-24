"""
Enhanced Sample CloudTrail Data Generator
Creates synthetic CloudTrail logs with attack labels for supervised ML training.

Attack Types:
1. privilege_escalation - IAM permission changes
2. data_exfiltration - Mass data downloads
3. reconnaissance - Enumeration of resources
4. credential_compromise - Failed auth / unusual access
5. normal - Legitimate activity
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
import argparse
from typing import Dict, List, Tuple


# Attack type definitions
ATTACK_TYPES = {
    'normal': 0,
    'privilege_escalation': 1,
    'data_exfiltration': 2,
    'reconnaissance': 3,
    'credential_compromise': 4
}


def generate_normal_event(timestamp, user_pool, service_pool) -> Tuple[Dict, int]:
    """
    Generate a normal CloudTrail event.
    
    Returns:
        Tuple of (event dict, label)
    """
    user = random.choice(user_pool)
    service = random.choice(service_pool)
    
    # Normal read operations during business hours
    read_events = {
        's3.amazonaws.com': ['GetObject', 'ListBucket', 'HeadObject'],
        'ec2.amazonaws.com': ['DescribeInstances', 'DescribeVolumes'],
        'rds.amazonaws.com': ['DescribeDBInstances'],
        'iam.amazonaws.com': ['GetUser', 'ListUsers'],
        'lambda.amazonaws.com': ['ListFunctions', 'GetFunction']
    }
    
    event_name = random.choice(read_events.get(service, ['DescribeInstances']))
    
    # Business hours: 9 AM - 5 PM on weekdays
    hour = random.randint(9, 17)
    timestamp = timestamp.replace(hour=hour)
    
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
                    "mfaAuthenticated": "true",  # Normal users have MFA
                    "creationDate": timestamp.isoformat() + "Z"
                }
            }
        },
        "eventTime": timestamp.isoformat() + "Z",
        "eventSource": service,
        "eventName": event_name,
        "awsRegion": random.choice(["us-east-1", "us-west-2"]),
        "sourceIPAddress": f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",  # Internal IP
        "userAgent": f"aws-cli/2.13.0 Python/3.11.{random.randint(0,5)}",
        "requestParameters": None,
        "responseElements": None,
        "requestID": f"req-{random.randint(100000, 999999)}",
        "eventID": f"evt-normal-{random.randint(100000, 999999)}-{random.randint(1000, 9999)}",
        "readOnly": True,
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012"
    }
    
    return event, ATTACK_TYPES['normal']


def generate_privilege_escalation(timestamp, user_pool) -> Tuple[Dict, int]:
    """
    Generate privilege escalation attack event.
    
    Characteristics:
    - IAM policy changes
    - Attempting to grant admin access
    - Off-hours activity
    - No MFA
    """
    user = random.choice(user_pool)
    
    # Off-hours: late night / early morning
    hour = random.choice([2, 3, 4, 23, 0, 1])
    timestamp = timestamp.replace(hour=hour)
    
    privilege_actions = [
        'AttachUserPolicy',
        'AttachRolePolicy',
        'PutUserPolicy',
        'PutRolePolicy',
        'CreateAccessKey',
        'UpdateAccessKey'
    ]
    
    event_name = random.choice(privilege_actions)
    
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
                    "mfaAuthenticated": "false",  # No MFA!
                    "creationDate": timestamp.isoformat() + "Z"
                }
            }
        },
        "eventTime": timestamp.isoformat() + "Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": f"{random.randint(100,200)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",  # External IP
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": {
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "userName": user
        },
        "errorCode": random.choice([None, "AccessDenied"]),  # May succeed or fail
        "requestID": f"req-{random.randint(100000, 999999)}",
        "eventID": f"evt-privesc-{random.randint(100000, 999999)}",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012"
    }
    
    return event, ATTACK_TYPES['privilege_escalation']


def generate_data_exfiltration(timestamp, user_pool) -> Tuple[Dict, int]:
    """
    Generate data exfiltration attack event.
    
    Characteristics:
    - Mass S3 downloads
    - Sensitive data access
    - High volume in short time
    - Unusual hours
    """
    user = random.choice(user_pool)
    
    # Off-hours
    hour = random.choice([22, 23, 0, 1, 2, 3])
    timestamp = timestamp.replace(hour=hour)
    
    sensitive_files = [
        "customer-pii/ssn-data.csv",
        "customer-pii/addresses.xlsx",
        "financial/credit-cards.csv",
        "financial/bank-accounts.json",
        "secrets/api-keys.txt",
        "secrets/database-credentials.json",
        "backups/production-db-backup.sql"
    ]
    
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
                    "mfaAuthenticated": "false",
                    "creationDate": timestamp.isoformat() + "Z"
                }
            }
        },
        "eventTime": timestamp.isoformat() + "Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "awsRegion": "us-east-1",
        "sourceIPAddress": f"{random.randint(50,100)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": {
            "bucketName": "sensitive-data-bucket",
            "key": random.choice(sensitive_files)
        },
        "requestID": f"req-{random.randint(100000, 999999)}",
        "eventID": f"evt-exfil-{random.randint(100000, 999999)}",
        "readOnly": True,
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012"
    }
    
    return event, ATTACK_TYPES['data_exfiltration']


def generate_reconnaissance(timestamp, user_pool) -> Tuple[Dict, int]:
    """
    Generate reconnaissance attack event.
    
    Characteristics:
    - Enumeration of resources
    - List/Describe API calls
    - Scanning multiple services
    - Rapid sequential calls
    """
    user = random.choice(user_pool)
    
    recon_actions = [
        ('ec2.amazonaws.com', 'DescribeInstances'),
        ('ec2.amazonaws.com', 'DescribeSecurityGroups'),
        ('ec2.amazonaws.com', 'DescribeVpcs'),
        ('s3.amazonaws.com', 'ListBuckets'),
        ('s3.amazonaws.com', 'GetBucketAcl'),
        ('iam.amazonaws.com', 'ListUsers'),
        ('iam.amazonaws.com', 'ListRoles'),
        ('iam.amazonaws.com', 'GetAccountSummary'),
        ('rds.amazonaws.com', 'DescribeDBInstances'),
        ('lambda.amazonaws.com', 'ListFunctions')
    ]
    
    service, action = random.choice(recon_actions)
    
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
                    "mfaAuthenticated": "false",
                    "creationDate": timestamp.isoformat() + "Z"
                }
            }
        },
        "eventTime": timestamp.isoformat() + "Z",
        "eventSource": service,
        "eventName": action,
        "awsRegion": "us-east-1",
        "sourceIPAddress": f"{random.randint(150,200)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "userAgent": "Boto3/1.26.0 Python/3.11.0",
        "requestParameters": None,
        "requestID": f"req-{random.randint(100000, 999999)}",
        "eventID": f"evt-recon-{random.randint(100000, 999999)}",
        "readOnly": True,
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012"
    }
    
    return event, ATTACK_TYPES['reconnaissance']


def generate_credential_compromise(timestamp, user_pool) -> Tuple[Dict, int]:
    """
    Generate credential compromise attack event.
    
    Characteristics:
    - Failed authentication attempts
    - Unusual geographic locations
    - Tor/VPN IP addresses
    - Console login attempts
    """
    user = random.choice(user_pool)
    
    # Tor exit nodes and suspicious IPs
    suspicious_ips = [
        "185.220.100.240",  # Tor
        "185.220.101.1",    # Tor
        "45.141.215.1",     # VPN
        "198.98.48.1",      # Proxy
    ]
    
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
                    "mfaAuthenticated": "false",
                    "creationDate": timestamp.isoformat() + "Z"
                }
            }
        },
        "eventTime": timestamp.isoformat() + "Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": random.choice(suspicious_ips),
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "errorCode": random.choice(["Failed authentication", None]),
        "errorMessage": random.choice(["Invalid username or password", None]),
        "requestID": f"req-{random.randint(100000, 999999)}",
        "eventID": f"evt-cred-{random.randint(100000, 999999)}",
        "readOnly": False,
        "eventType": "AwsConsoleSignIn",
        "recipientAccountId": "123456789012"
    }
    
    return event, ATTACK_TYPES['credential_compromise']


def generate_labeled_dataset(
    num_normal=800,
    num_privesc=50,
    num_exfil=50,
    num_recon=50,
    num_cred=50,
    output_dir='data/labeled',
    events_filename='labeled_events.json',
    labels_filename='labels.json'
) -> None:
    """
    Generate labeled dataset for supervised learning.
    
    Args:
        num_normal: Number of normal events
        num_privesc: Number of privilege escalation events
        num_exfil: Number of data exfiltration events
        num_recon: Number of reconnaissance events
        num_cred: Number of credential compromise events
        output_dir: Output directory
        events_filename: CloudTrail events filename
        labels_filename: Labels filename
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
    labels = []
    event_ids = []
    start_time = datetime.now() - timedelta(days=7)
    
    print(f"Generating {num_normal} normal events...")
    for i in range(num_normal):
        timestamp = start_time + timedelta(minutes=random.randint(0, 7*24*60))
        event, label = generate_normal_event(timestamp, user_pool, service_pool)
        events.append(event)
        labels.append(label)
        event_ids.append(event['eventID'])
    
    print(f"Generating {num_privesc} privilege escalation events...")
    for i in range(num_privesc):
        timestamp = start_time + timedelta(minutes=random.randint(0, 7*24*60))
        event, label = generate_privilege_escalation(timestamp, user_pool)
        events.append(event)
        labels.append(label)
        event_ids.append(event['eventID'])
    
    print(f"Generating {num_exfil} data exfiltration events...")
    for i in range(num_exfil):
        timestamp = start_time + timedelta(minutes=random.randint(0, 7*24*60))
        event, label = generate_data_exfiltration(timestamp, user_pool)
        events.append(event)
        labels.append(label)
        event_ids.append(event['eventID'])
    
    print(f"Generating {num_recon} reconnaissance events...")
    for i in range(num_recon):
        timestamp = start_time + timedelta(minutes=random.randint(0, 7*24*60))
        event, label = generate_reconnaissance(timestamp, user_pool)
        events.append(event)
        labels.append(label)
        event_ids.append(event['eventID'])
    
    print(f"Generating {num_cred} credential compromise events...")
    for i in range(num_cred):
        timestamp = start_time + timedelta(minutes=random.randint(0, 7*24*60))
        event, label = generate_credential_compromise(timestamp, user_pool)
        events.append(event)
        labels.append(label)
        event_ids.append(event['eventID'])
    
    # Sort by timestamp
    combined = list(zip(events, labels, event_ids))
    combined.sort(key=lambda x: x[0]['eventTime'])
    events, labels, event_ids = zip(*combined)
    
    # Create CloudTrail log structure
    cloudtrail_data = {
        "Records": list(events)
    }
    
    # Create labels mapping
    labels_data = {
        "event_labels": {
            event_id: {
                "label": int(label),
                "attack_type": [k for k, v in ATTACK_TYPES.items() if v == label][0]
            }
            for event_id, label in zip(event_ids, labels)
        },
        "attack_type_mapping": ATTACK_TYPES,
        "statistics": {
            "total_events": len(events),
            "normal": labels.count(ATTACK_TYPES['normal']),
            "privilege_escalation": labels.count(ATTACK_TYPES['privilege_escalation']),
            "data_exfiltration": labels.count(ATTACK_TYPES['data_exfiltration']),
            "reconnaissance": labels.count(ATTACK_TYPES['reconnaissance']),
            "credential_compromise": labels.count(ATTACK_TYPES['credential_compromise'])
        }
    }
    
    # Save files
    events_file = output_path / events_filename
    labels_file = output_path / labels_filename
    
    with open(events_file, 'w') as f:
        json.dump(cloudtrail_data, f, indent=2)
    
    with open(labels_file, 'w') as f:
        json.dump(labels_data, f, indent=2)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Dataset Generation Complete!")
    print(f"{'='*60}")
    print(f"Total events: {len(events)}")
    print(f"\nClass distribution:")
    print(f"  Normal:                 {labels.count(ATTACK_TYPES['normal']):4d} ({labels.count(ATTACK_TYPES['normal'])/len(labels)*100:.1f}%)")
    print(f"  Privilege Escalation:   {labels.count(ATTACK_TYPES['privilege_escalation']):4d} ({labels.count(ATTACK_TYPES['privilege_escalation'])/len(labels)*100:.1f}%)")
    print(f"  Data Exfiltration:      {labels.count(ATTACK_TYPES['data_exfiltration']):4d} ({labels.count(ATTACK_TYPES['data_exfiltration'])/len(labels)*100:.1f}%)")
    print(f"  Reconnaissance:         {labels.count(ATTACK_TYPES['reconnaissance']):4d} ({labels.count(ATTACK_TYPES['reconnaissance'])/len(labels)*100:.1f}%)")
    print(f"  Credential Compromise:  {labels.count(ATTACK_TYPES['credential_compromise']):4d} ({labels.count(ATTACK_TYPES['credential_compromise'])/len(labels)*100:.1f}%)")
    print(f"\nFiles saved:")
    print(f"  Events: {events_file}")
    print(f"  Labels: {labels_file}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description='Generate labeled CloudTrail dataset')
    parser.add_argument('--normal', type=int, default=800,
                       help='Number of normal events (default: 800)')
    parser.add_argument('--privesc', type=int, default=50,
                       help='Number of privilege escalation events (default: 50)')
    parser.add_argument('--exfil', type=int, default=50,
                       help='Number of data exfiltration events (default: 50)')
    parser.add_argument('--recon', type=int, default=50,
                       help='Number of reconnaissance events (default: 50)')
    parser.add_argument('--cred', type=int, default=50,
                       help='Number of credential compromise events (default: 50)')
    parser.add_argument('--output', type=str, default='data/labeled',
                       help='Output directory (default: data/labeled)')
    
    args = parser.parse_args()
    
    generate_labeled_dataset(
        num_normal=args.normal,
        num_privesc=args.privesc,
        num_exfil=args.exfil,
        num_recon=args.recon,
        num_cred=args.cred,
        output_dir=args.output
    )


if __name__ == "__main__":
    main()
