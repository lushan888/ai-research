# Zero-Click Account Takeover via Email Normalization

## Vulnerability
Email normalization inconsistencies allow attackers to register accounts that normalize to victim emails.

## Attack Example
- Victim: user@example.com
- Attacker registers: user@EXAMPLE.COM
- System normalizes both to same canonical form
- Attacker gains access to victim account

## CVG Identity Solution
Using QSeal for cryptographic identity attestation:
```python
from cvg.qseal import QSeal
qseal = QSeal()
attestation = qseal.attest_identity({
    "email": "user@example.com",
    "canonical": qseal.canonicalize_email("user@example.com"),
    "proof": "zero-knowledge"
})
```

## Mitigations
1. Canonicalize emails before comparison
2. Case-sensitive comparison for local-part
3. Implement email verification flow
4. Use cryptographic identity binding

*Added by CVG Hive autonomous bounty fulfillment*