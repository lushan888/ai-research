"""
Second-Order SQL Injection via Stored XSS Data Fix
Bounty #798 ($150)
=========================================
Vulnerability: User comments stored safely with parameterized queries.
BUT admin CSV export concatenates stored data into SQL:
SELECT * FROM comments WHERE id IN (user_ids)
Attacker stores malicious input, triggers export → SQL injection.

Fix: Always parameterize queries + second-order sanitization.
"""

import re
from typing import List, Tuple, Dict, Any


class SecondOrderSQLSanitizer:
    """
    Prevents second-order SQL injection.
    Sanitizes data read from database before use in queries.
    """

    SQL_INJECTION_PATTERNS = [
        re.compile(r"['\";\\]"),
        re.compile(r"--|#|/\*|\*/"),
        re.compile(r"\bUNION\b", re.I),
        re.compile(r"\bSELECT\b", re.I),
        re.compile(r"\bINSERT\b", re.I),
        re.compile(r"\bUPDATE\b", re.I),
        re.compile(r"\bDELETE\b", re.I),
        re.compile(r"\bDROP\b", re.I),
        re.compile(r"\bEXEC\b", re.I),
        re.compile(r"\bOR\b.*=.*=", re.I),
        re.compile(r"\bAND\b.*=.*=", re.I),
        re.compile(r"\bWAITFOR\b", re.I),
        re.compile(r"\bSLEEP\b", re.I),
        re.compile(r"\bBENCHMARK\b", re.I),
        re.compile(r"\bINTO\s+OUTFILE\b", re.I),
        re.compile(r"\bINFORMATION_SCHEMA\b", re.I),
        re.compile(r"0x[0-9a-fA-F]{2,}"),
        re.compile(r"CHAR\(|CHR\("),
        re.compile(r"CONCAT\(|CONCAT_WS\("),
    ]

    @classmethod
    def sanitize_value(cls, value: str) -> str:
        """Sanitize a value read from database for safe query reuse."""
        sanitized = value.replace("'", "''")
        sanitized = sanitized.replace("\\", "\\\\")
        sanitized = sanitized.replace("\x00", "")
        return sanitized

    @classmethod
    def detect_sql_injection(cls, value: str) -> List[str]:
        """Detect SQL injection patterns."""
        findings = []
        for pattern in cls.SQL_INJECTION_PATTERNS:
            matches = pattern.findall(value)
            if matches:
                findings.append(f"Pattern: {matches[:3]}")
        return findings


class ParameterizedQueryBuilder:
    """Builds parameterized queries — no string concatenation."""

    def __init__(self, placeholder: str = "?"):
        self._placeholder = placeholder

    def build_in_clause(self, column: str, values: List) -> Tuple[str, List]:
        """Parameterized IN clause. Returns (sql, params)."""
        placeholders = ",".join([self._placeholder] * len(values))
        return f"{column} IN ({placeholders})", values

    def build_select(self, table: str, columns: List[str],
                     conditions: List[Tuple]) -> Tuple[str, List]:
        """Parameterized SELECT. conditions: [(col, op, val), ...]"""
        col_str = ", ".join(columns)
        where_parts = []
        params = []
        for col, op, val in conditions:
            where_parts.append(f"{col} {op} {self._placeholder}")
            params.append(val)
        return f"SELECT {col_str} FROM {table} WHERE {' AND '.join(where_parts)}", params

    def build_insert(self, table: str, data: Dict[str, Any]) -> Tuple[str, List]:
        """Parameterized INSERT."""
        cols = ", ".join(data.keys())
        phs = ", ".join([self._placeholder] * len(data))
        return f"INSERT INTO {table} ({cols}) VALUES ({phs})", list(data.values())


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== Second-Order SQL Injection Prevention ===")
    print()

    print("Attack:")
    print("  1. User submits: '; DROP TABLE comments;--")
    print("  2. Stored safely (parameterized INSERT)")
    print("  3. Admin exports CSV, concatenates: ")
    print("     SELECT * FROM comments WHERE id IN ('; DROP TABLE comments;--')")
    print("  4. → SQL injection!")
    print()

    malicious = "'; DROP TABLE comments;--"
    print(f"Input: {malicious}")
    print(f"Injection patterns: {SecondOrderSQLSanitizer.detect_sql_injection(malicious)}")
    print(f"Sanitized: {SecondOrderSQLSanitizer.sanitize_value(malicious)}")
    print()
    print("Measures:")
    print("✓ Parameterized queries for ALL operations")
    print("✓ Second-order input sanitization")
    print("✓ SQL injection pattern detection")
    print("✓ Parameterized IN clause builder")
    print("✓ Never concatenate stored data into SQL strings")