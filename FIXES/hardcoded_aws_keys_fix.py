"""
Hardcoded AWS Keys in Public Artifact Fix
Bounty #800 ($180)
=========================================
Vulnerability: CI/CD artifacts contain hardcoded AWS keys.
Attackers extract credentials and take over cloud resources.

Fix: Use STS temporary credentials + CI secret scanning + env vars.
"""

import os
import re
import json
from typing import List, Optional


class AWSCredentialScanner:
    """
    Scans for hardcoded AWS credentials in code and artifacts.
    """

    # AWS credential patterns
    AWS_KEY_PATTERNS = [
        re.compile(r'AKIA[0-9A-Z]{16}'),  # Access Key ID
        re.compile(r'(?i)aws_access_key_id\s*[=:]\s*["\']?[A-Z0-9]{20}["\']?'),
        re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}["\']?'),
        re.compile(r'(?i)AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY'),
        re.compile(r'(?i)aws\.accessKeyId|aws\.secretAccessKey'),
    ]

    @staticmethod
    def scan_file(filepath: str) -> List[dict]:
        """Scan a file for hardcoded AWS credentials."""
        findings = []
        try:
            with open(filepath, 'r') as f:
                for i, line in enumerate(f, 1):
                    for pattern in AWSCredentialScanner.AWS_KEY_PATTERNS:
                        if pattern.search(line):
                            findings.append({
                                'file': filepath,
                                'line': i,
                                'pattern': pattern.pattern[:30],
                            })
                            break
        except (IOError, UnicodeDecodeError):
            pass
        return findings

    @staticmethod
    def scan_directory(directory: str) -> List[dict]:
        """Recursively scan a directory for hardcoded keys."""
        findings = []
        for root, dirs, files in os.walk(directory):
            # Skip .git and node_modules
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__')]
            for f in files:
                path = os.path.join(root, f)
                findings.extend(AWSCredentialScanner.scan_file(path))
        return findings


class SecureCredentialManager:
    """
    Manages credentials securely.
    Uses STS temporary credentials instead of hardcoded keys.
    """

    def __init__(self):
        # NEVER store credentials as attributes
        pass

    @staticmethod
    def get_temporary_credentials(duration: int = 3600) -> dict:
        """
        Get STS temporary credentials.
        No hardcoded keys in code or artifacts.
        """
        import boto3

        sts = boto3.client('sts')
        response = sts.get_session_token(DurationSeconds=duration)

        return {
            'access_key_id': response['Credentials']['AccessKeyId'],
            'secret_access_key': response['Credentials']['SecretAccessKey'],
            'session_token': response['Credentials']['SessionToken'],
            'expiration': response['Credentials']['Expiration'].isoformat(),
        }

    @staticmethod
    def assume_role(role_arn: str, session_name: str) -> dict:
        """
        Assume an IAM role for temporary credentials.
        """
        import boto3

        sts = boto3.client('sts')
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
        )

        return {
            'access_key_id': response['Credentials']['AccessKeyId'],
            'secret_access_key': response['Credentials']['SecretAccessKey'],
            'session_token': response['Credentials']['SessionToken'],
        }


# ========== CI Script for Secret Scanning ==========
CI_SECRET_SCAN_SCRIPT = """#!/bin/bash
# CI secret scanning step
# Add to CI/CD pipeline to prevent hardcoded credentials

echo "🔍 Scanning for hardcoded AWS credentials..."

# Check for AWS access key patterns
FOUND=$(grep -rn "AKIA[0-9A-Z]\\{16\\}" --include="*.py" --include="*.js" --include="*.json" --include="*.yaml" --include="*.env" . 2>/dev/null || true)

if [ -n "$FOUND" ]; then
    echo "❌ Hardcoded AWS credentials found!"
    echo "$FOUND"
    exit 1
fi

# Check for AWS secret key patterns
FOUND_SECRET=$(grep -rn "aws_secret_access_key" --include="*.py" --include="*.js" --include="*.json" --include="*.yaml" --include="*.env" . 2>/dev/null || true)

if [ -n "$FOUND_SECRET" ]; then
    echo "❌ Hardcoded AWS secret keys found!"
    echo "$FOUND_SECRET"
    exit 1
fi

# Check for .env files in artifacts
if [ -f ".env" ]; then
    echo "❌ .env file found in build artifact!"
    exit 1
fi

echo "✅ No hardcoded credentials found"
exit 0
"""


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== Hardcoded AWS Keys Prevention ===")
    print()

    print("Security measures:")
    print("1. ✓ STS temporary credentials (no hardcoded keys)")
    print("2. ✓ IAM Role assumption (assume_role)")
    print("3. ✓ CI secret scanning (grep for AKIA patterns)")
    print("4. ✓ .env file exclusion from artifacts")
    print("5. ✓ Environment variables for runtime config")
    print()
    print("Before:")
    print("  aws_access_key_id = 'AKIA1234567890ABCDEF'")
    print("  → Key exposed in Docker image!")
    print()
    print("After:")
    print("  credentials = sts.get_session_token()")
    print("  → Temporary, rotated, never hardcoded!")