# Fix: AWS IAM Privilege Escalation via PassRole + EC2

## Vulnerability

IAM policies that allow both `iam:PassRole` and `ec2:RunInstances` with wildcard resources enable privilege escalation. An attacker can launch an EC2 instance with a high-privilege IAM role attached and extract temporary credentials via user-data scripts.

## Vulnerable Policy

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:RunInstances",
                "iam:PassRole"
            ],
            "Resource": "*"
        }
    ]
}
```

## Fix Implementation

### 1. Secure IAM Policy (Least Privilege)

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PassRoleToEC2",
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": [
                "arn:aws:iam::123456789012:role/ec2-web-server-role",
                "arn:aws:iam::123456789012:role/ec2-app-role"
            ],
            "Condition": {
                "StringEquals": {
                    "iam:PassedToService": "ec2.amazonaws.com"
                },
                "ArnLike": {
                    "aws:SourceArn": "arn:aws:ec2:*:123456789012:instance/*"
                }
            }
        },
        {
            "Sid": "EC2RunInstances",
            "Effect": "Allow",
            "Action": "ec2:RunInstances",
            "Resource": [
                "arn:aws:ec2:*:123456789012:instance/*",
                "arn:aws:ec2:*:123456789012:volume/*",
                "arn:aws:ec2:*:123456789012:security-group/*"
            ],
            "Condition": {
                "StringEquals": {
                    "ec2:InstanceType": ["t3.micro", "t3.small"]
                }
            }
        },
        {
            "Sid": "DenyPassSensitiveRoles",
            "Effect": "Deny",
            "Action": "iam:PassRole",
            "Resource": [
                "arn:aws:iam::123456789012:role/admin",
                "arn:aws:iam::123456789012:role/AdministratorAccess"
            ]
        }
    ]
}
```

### 2. Security Checklist

- [x] PassRole restricted to specific role ARN whitelist
- [x] Wildcard Resource removed from PassRole statement
- [x] `aws:SourceArn` condition key added
- [x] `iam:PassedToService` condition restricts to EC2 service
- [x] Sensitive roles explicitly denied
- [x] EC2 RunInstances scoped to specific resource types

## References

- AWS IAM: Granting PassRole Permission
- CWE-269: Improper Privilege Management
- Rhino Security Labs: IAM Privilege Escalation Methods

## Wallet for Bounty Payment
- **ETH/EVM (Ethereum, Polygon, Base, Optimism, Arbitrum):** `0x415b24ab21388dbfb9c4da97cb1ab2b53ff21e29`
- **SOL (Solana):** `J6pwNJNbjYx7UHAvZK369kYRJHim8JVbeFEHRSqtFMjv`