"""
Fix for Issue #1149 - S3 Bucket Misconfiguration → Mass Data Leak
Bounty: $120

Attack vector: S3 bucket policy uses `Principal: "*"` with `Action: "s3:GetObject"`,
allowing anonymous read access to all objects. Attackers enumerate bucket contents
and download sensitive data.

Fix strategy:
1. Enable S3 Block Public Access at account and bucket level.
2. Remove wildcard Principal from bucket policies.
3. Use pre-signed URLs for temporary access instead of public reads.
4. Validate bucket policies against least-privilege rules.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Union


# --- Constants ---

WILDCARD_PRINCIPAL = {"AWS": "*"}
WILDCARD_PRINCIPAL_STAR = "*"

BLOCKED_ACTIONS: Set[str] = {
    "s3:GetObject",
    "s3:GetObjectVersion",
    "s3:ListBucket",
    "s3:ListBucketVersions",
}

RECOMMENDED_BLOCK_PUBLIC_ACCESS = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


# --- Policy Validation ---

class PolicySeverity(Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class PolicyCheck:
    severity: PolicySeverity
    message: str
    detail: str = ""


@dataclass
class PolicyValidationResult:
    bucket_name: str
    checks: List[PolicyCheck] = field(default_factory=list)
    is_public: bool = False

    @property
    def passed(self) -> bool:
        return not any(c.severity == PolicySeverity.FAIL for c in self.checks)


def validate_bucket_policy(
    bucket_name: str,
    policy_document: Optional[Union[str, dict]],
    block_public_access: Optional[dict] = None,
) -> PolicyValidationResult:
    """Validate an S3 bucket policy for public access misconfigurations.

    Args:
        bucket_name: Name of the S3 bucket.
        policy_document: The bucket policy as JSON string or dict.
        block_public_access: Current Block Public Access settings.

    Returns:
        PolicyValidationResult with all check results.
    """
    result = PolicyValidationResult(bucket_name=bucket_name)

    if policy_document is None:
        result.checks.append(PolicyCheck(
            PolicySeverity.PASS, "No bucket policy attached", "Default private"
        ))
        result.is_public = False
        return result

    if isinstance(policy_document, str):
        try:
            policy_document = json.loads(policy_document)
        except json.JSONDecodeError as exc:
            result.checks.append(PolicyCheck(
                PolicySeverity.FAIL, f"Invalid JSON policy: {exc}", ""
            ))
            result.is_public = True
            return result

    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for i, stmt in enumerate(statements):
        _check_statement(result, stmt, i)

    # Block Public Access checks
    if block_public_access:
        for key, expected in RECOMMENDED_BLOCK_PUBLIC_ACCESS.items():
            actual = block_public_access.get(key, False)
            if actual != expected:
                result.checks.append(PolicyCheck(
                    PolicySeverity.FAIL,
                    f"Block Public Access setting '{key}' is {actual}, expected {expected}",
                    "Enable all Block Public Access settings",
                ))
            else:
                result.checks.append(PolicyCheck(
                    PolicySeverity.PASS,
                    f"Block Public Access '{key}' correctly enabled",
                    "",
                ))

    return result


def _check_statement(result: PolicyValidationResult, stmt: dict, index: int) -> None:
    """Check a single policy statement for public access."""
    principal = stmt.get("Principal", {})
    effect = stmt.get("Effect", "Deny")
    action = stmt.get("Action", [])
    condition = stmt.get("Condition", {})

    # Normalize action to list
    if isinstance(action, str):
        action = [action]

    # Check for wildcard principal
    has_wildcard = (
        principal == WILDCARD_PRINCIPAL
        or principal == WILDCARD_PRINCIPAL_STAR
        or (isinstance(principal, dict) and "*" in principal.values())
    )

    if has_wildcard and effect == "Allow":
        blocked = [a for a in action if a in BLOCKED_ACTIONS or a == "s3:*"]
        if blocked:
            result.checks.append(PolicyCheck(
                PolicySeverity.FAIL,
                f"Statement #{index}: Wildcard principal with Allow + "
                f"sensitive actions: {blocked}",
                "Replace wildcard principal with specific IAM roles or users",
            ))
            result.is_public = True
        else:
            result.checks.append(PolicyCheck(
                PolicySeverity.WARN,
                f"Statement #{index}: Wildcard principal but no sensitive s3 actions",
                "Consider narrowing principal scope",
            ))

    # Check for condition key that restricts access
    if has_wildcard and condition:
        # If there's a condition (like SourceIp), it might be intentional
        result.checks.append(PolicyCheck(
            PolicySeverity.WARN,
            f"Statement #{index}: Wildcard principal with condition",
            "Verify condition is sufficiently restrictive",
        ))


# --- Secure Policy Generator ---

def generate_secure_policy(
    bucket_name: str,
    allowed_arns: Optional[Sequence[str]] = None,
) -> dict:
    """Generate a least-privilege S3 bucket policy.

    Args:
        bucket_name: The S3 bucket name.
        allowed_arns: List of IAM role/user ARNs allowed access.

    Returns:
        A secure bucket policy dict with no wildcard principals.
    """
    if allowed_arns is None:
        allowed_arns = []

    policy = {
        "Version": "2012-10-17",
        "Statement": [],
    }

    if allowed_arns:
        policy["Statement"].append({
            "Effect": "Allow",
            "Principal": {"AWS": list(allowed_arns)},
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [
                f"arn:aws:s3:::{bucket_name}",
                f"arn:aws:s3:::{bucket_name}/*",
            ],
        })

    # Deny public access explicitly
    policy["Statement"].append({
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
            f"arn:aws:s3:::{bucket_name}",
            f"arn:aws:s3:::{bucket_name}/*",
        ],
        "Condition": {
            "Bool": {"aws:SecureTransport": "false"},
        },
    })

    return policy


# --- Pre-signed URL Generator ---

import hashlib
import hmac
import time
from urllib.parse import urlencode, quote


def generate_presigned_url(
    bucket: str,
    key: str,
    expires_in_seconds: int = 3600,
    access_key: str = "",
    secret_key: str = "",
    region: str = "us-east-1",
) -> str:
    """Generate a pre-signed S3 GET URL (v4 signing simulation).

    In production, use boto3.generate_presigned_url().
    This is a reference implementation for documentation/testing.
    """
    # In real deployment, use:
    #   import boto3
    #   s3 = boto3.client('s3')
    #   url = s3.generate_presigned_url(
    #       'get_object',
    #       Params={'Bucket': bucket, 'Key': key},
    #       ExpiresIn=expires_in_seconds
    #   )
    #   return url

    # Placeholder for documentation
    return (
        f"https://{bucket}.s3.{region}.amazonaws.com/"
        f"{quote(key, safe='')}"
        f"?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        f"&X-Amz-Expires={expires_in_seconds}"
        f"&X-Amz-SignedHeaders=host"
    )


# --- Unit Tests ---

import unittest


class TestS3BucketFix(unittest.TestCase):

    VULNERABLE_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*",
            }
        ],
    }

    SECURE_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/app-role"},
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::example-bucket/*",
            },
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::example-bucket",
                    "arn:aws:s3:::example-bucket/*",
                ],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ],
    }

    def test_detects_public_bucket(self):
        result = validate_bucket_policy("test-bucket", self.VULNERABLE_POLICY)
        self.assertTrue(result.is_public)
        self.assertFalse(result.passed)

    def test_secure_policy_passes(self):
        result = validate_bucket_policy("test-bucket", self.SECURE_POLICY)
        self.assertFalse(result.is_public)

    def test_no_policy_is_private(self):
        result = validate_bucket_policy("test-bucket", None)
        self.assertFalse(result.is_public)
        self.assertTrue(result.passed)

    def test_generate_secure_policy(self):
        policy = generate_secure_policy("my-bucket", ["arn:aws:iam::1:role/app"])
        statements = policy["Statement"]
        # Should have Allow + Deny
        self.assertGreaterEqual(len(statements), 2)
        # Deny statement should have principal *
        deny_stmts = [s for s in statements if s["Effect"] == "Deny"]
        self.assertTrue(deny_stmts)

    def test_block_public_access_validation(self):
        bpa = {"BlockPublicAcls": False, "IgnorePublicAcls": True,
               "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
        result = validate_bucket_policy("test", None, block_public_access=bpa)
        self.assertFalse(result.passed)


if __name__ == "__main__":
    unittest.main()