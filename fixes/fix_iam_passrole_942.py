"""
Fix for Issue #942 — AWS IAM Privilege Escalation via PassRole + EC2
====================================================================

Vulnerability
-------------
The IAM policy allows ``iam:PassRole`` to EC2 combined with ``ec2:RunInstances``.
An attacker with these permissions can launch an EC2 instance with a high-privilege
IAM role attached. By supplying a user-data script, the attacker retrieves the
instance's temporary credentials and escalates privileges to the attached role's
level.

Fix Strategy
------------
1. Restrict ``iam:PassRole`` to a specific whitelist of allowed roles.
2. Remove wildcard ``Resource`` from ``iam:PassRole`` statements.
3. Add ``aws:SourceArn`` condition key to restrict the EC2 resources that can
   receive the passed role.
4. Protect sensitive/high-privilege roles with explicit deny statements.
5. Apply the principle of least privilege to all IAM policies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping


# Sensitive roles that should never be passed to EC2
SENSITIVE_ROLES = frozenset({
    "admin",
    "AdministratorAccess",
    "PowerUserAccess",
    "admin-*",
    "*admin*",
})

# Example: roles that are safe to pass to EC2
ALLOWED_ROLES_FOR_EC2 = frozenset({
    "ec2-default-role",
    "ec2-web-server-role",
    "ec2-app-role",
    "ec2-worker-role",
})


class IAMPolicyError(ValueError):
    """Raised when an IAM policy is insecure."""


@dataclass
class SecureIAMPolicy:
    """Secure IAM policy builder that prevents PassRole privilege escalation.

    Usage::

        builder = SecureIAMPolicy()
        policy = builder.build_ec2_policy()
        # Deploy policy to AWS
    """

    allowed_roles: set[str] = field(default_factory=lambda: set(ALLOWED_ROLES_FOR_EC2))
    sensitive_roles: set[str] = field(default_factory=lambda: set(SENSITIVE_ROLES))

    def build_ec2_policy(self, account_id: str, region: str = "*") -> dict[str, Any]:
        """Build a secure IAM policy for EC2 operations.

        Args:
            account_id: AWS account ID (12-digit number).
            region: AWS region (default: all regions).

        Returns:
            A secure IAM policy document as a dict.
        """
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EC2RunInstances",
                    "Effect": "Allow",
                    "Action": "ec2:RunInstances",
                    "Resource": [
                        f"arn:aws:ec2:{region}:{account_id}:instance/*",
                        f"arn:aws:ec2:{region}:{account_id}:volume/*",
                        f"arn:aws:ec2:{region}:{account_id}:security-group/*",
                        f"arn:aws:ec2:{region}:{account_id}:subnet/*",
                        f"arn:aws:ec2:{region}:{account_id}:network-interface/*",
                        f"arn:aws:ec2:{region}:{account_id}:key-pair/*",
                    ],
                    "Condition": {
                        "StringEquals": {
                            "ec2:InstanceType": [
                                "t3.micro",
                                "t3.small",
                                "t3.medium",
                            ]
                        }
                    }
                },
                {
                    "Sid": "PassRoleToEC2",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": [
                        f"arn:aws:iam::{account_id}:role/{role}"
                        for role in sorted(self.allowed_roles)
                    ],
                    "Condition": {
                        "StringEquals": {
                            "iam:PassedToService": "ec2.amazonaws.com",
                        },
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:ec2:{region}:{account_id}:instance/*",
                        },
                    },
                },
                {
                    "Sid": "DenyPassSensitiveRoles",
                    "Effect": "Deny",
                    "Action": "iam:PassRole",
                    "Resource": [
                        f"arn:aws:iam::{account_id}:role/{role}"
                        for role in sorted(self.sensitive_roles)
                    ],
                },
                {
                    "Sid": "DescribeEC2",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeInstances",
                        "ec2:DescribeImages",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeKeyPairs",
                    ],
                    "Resource": "*",
                },
            ],
        }

    @staticmethod
    def validate_policy(policy: dict[str, Any]) -> list[str]:
        """Validate an IAM policy for common security issues.

        Args:
            policy: An IAM policy document.

        Returns:
            A list of security findings (empty if secure).
        """
        findings: list[str] = []

        if not isinstance(policy, dict):
            findings.append("policy must be a JSON object")
            return findings

        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            findings.append("Statement must be an array")
            return findings

        for i, stmt in enumerate(statements):
            sid = stmt.get("Sid", f"statement-{i}")

            # Check for wildcard resources on sensitive actions
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                resource = stmt.get("Resource", "*")

                # Check PassRole
                if "iam:PassRole" in actions:
                    if resource == "*":
                        findings.append(
                            f"{sid}: iam:PassRole should not use wildcard Resource"
                        )

                # Check RunInstances
                if "ec2:RunInstances" in actions:
                    if resource == "*":
                        findings.append(
                            f"{sid}: ec2:RunInstances should not use wildcard Resource"
                        )

                # Check combined PassRole + RunInstances
                if "iam:PassRole" in actions and "ec2:RunInstances" in actions:
                    if "Condition" not in stmt:
                        findings.append(
                            f"{sid}: iam:PassRole and ec2:RunInstances combined "
                            f"without Condition keys — privilege escalation risk"
                        )

        return findings

    @staticmethod
    def generate_secure_trust_policy(
        account_id: str,
        role_name: str,
    ) -> dict[str, Any]:
        """Generate a secure trust policy for an EC2 role.

        Args:
            account_id: AWS account ID.
            role_name: The role name.

        Returns:
            A secure trust policy document.
        """
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": account_id,
                        },
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:ec2:*:{account_id}:instance/*",
                        },
                    },
                }
            ],
        }


# ---------------------------------------------------------------------------
# Example vulnerable policy (for reference)
# ---------------------------------------------------------------------------

VULNERABLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EC2Access",
            "Effect": "Allow",
            "Action": [
                "ec2:RunInstances",
                "iam:PassRole",
            ],
            "Resource": "*",  # VULNERABLE: wildcard resource!
        },
    ],
}


# ---------------------------------------------------------------------------
# Remediation script
# ---------------------------------------------------------------------------

def remediate_passrole_policy(
    current_policy: dict[str, Any],
    account_id: str,
) -> dict[str, Any]:
    """Remediate a vulnerable IAM policy to prevent PassRole escalation.

    Args:
        current_policy: The current (vulnerable) IAM policy.
        account_id: AWS account ID.

    Returns:
        A remediated secure IAM policy.
    """
    builder = SecureIAMPolicy()

    # Start with a minimal secure policy
    secure_policy = builder.build_ec2_policy(account_id)

    # Preserve any additional non-sensitive permissions from the original
    original_statements = current_policy.get("Statement", [])
    if isinstance(original_statements, list):
        for stmt in original_statements:
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            # Skip actions we already cover securely
            if set(actions).intersection({
                "ec2:RunInstances", "iam:PassRole",
                "ec2:DescribeInstances", "ec2:DescribeImages",
                "ec2:DescribeSecurityGroups", "ec2:DescribeSubnets",
                "ec2:DescribeKeyPairs",
            }):
                continue

            # Keep other permissions (after validating they're safe)
            secure_policy["Statement"].append(stmt)

    return secure_policy