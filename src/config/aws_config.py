"""
Secure AWS configuration using temporary credentials.
Fixes hardcoded AWS keys in public artifacts vulnerability.
"""
import os
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from typing import Optional, Tuple


def get_aws_session() -> boto3.Session:
    """
    Get AWS session using IAM Role or STS temporary credentials.
    Never hardcodes AWS access keys in source code or build artifacts.
    
    Resolution order:
    1. IAM Role (ECS/EKS/EC2 instance profile)
    2. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
    3. AWS credentials file (~/.aws/credentials)
    
    Returns:
        boto3.Session configured with temporary credentials
    """
    session = boto3.Session()
    
    # Verify we have credentials and they are valid
    sts = session.client('sts')
    try:
        identity = sts.get_caller_identity()
        print(f"Authenticated as: {identity['Arn']}")
        return session
    except (NoCredentialsError, ClientError) as e:
        print(f"Warning: No valid AWS credentials found: {e}")
        return session


def get_temporary_credentials(duration_seconds: int = 3600) -> Optional[dict]:
    """
    Request temporary STS credentials with limited duration.
    
    Args:
        duration_seconds: Credential validity duration (default: 1 hour)
    
    Returns:
        Dict with temporary credentials or None if unavailable
    """
    session = boto3.Session()
    sts = session.client('sts')
    
    try:
        response = sts.get_session_token(DurationSeconds=duration_seconds)
        creds = response['Credentials']
        return {
            'aws_access_key_id': creds['AccessKeyId'],
            'aws_secret_access_key': creds['SecretAccessKey'],
            'aws_session_token': creds['SessionToken'],
            'expiration': creds['Expiration'].isoformat()
        }
    except (NoCredentialsError, ClientError) as e:
        print(f"Cannot get temporary credentials: {e}")
        return None


def validate_no_hardcoded_keys():
    """
    CI gate: Validate that no AWS keys are hardcoded in the codebase.
    Should be run as part of CI/CD pipeline.
    
    Returns:
        Tuple of (passed: bool, violations: List[str])
    """
    import re
    import glob
    
    violations = []
    patterns = [
        r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID pattern
        r'(?i)aws_access_key_id\s*=\s*["\'](?!\$)',
        r'(?i)aws_secret_access_key\s*=\s*["\'](?!\$)',
    ]
    
    for pattern in patterns:
        regex = re.compile(pattern)
        for filepath in glob.glob('**/*.py', recursive=True) + glob.glob('**/*.ts', recursive=True):
            if 'node_modules' in filepath or '.git' in filepath:
                continue
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                for match in regex.finditer(content):
                    violations.append(f"{filepath}:{match.group()}")
            except (IOError, UnicodeDecodeError):
                continue
    
    return len(violations) == 0, violations
