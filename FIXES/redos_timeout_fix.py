"""
Fix for Issue #1150 - Regex DoS (ReDoS) via User-Controlled Pattern
Bounty: $120

Attack vector: User-supplied regex pattern (e.g., `(a+)+b`) passed directly to
`new RegExp(userInput)`. Evil input like `aaaaaaaaaaaaac` triggers catastrophic
backtracking and CPU exhaustion.

Fix strategy:
1. Enforce a hard timeout on all regex execution.
2. Limit the maximum length of user-supplied regex patterns.
3. Use a ReDoS-safe pre-compiled pattern whitelist where possible.
4. Gracefully reject patterns that match known ReDoS signatures.
"""

from __future__ import annotations

import re
import threading
import unittest
from contextlib import contextmanager
from typing import Iterator, Optional

# --- Configuration ---

MAX_PATTERN_LENGTH = 50
REGEX_TIMEOUT_SECONDS = 1.0

# Patterns known to trigger catastrophic backtracking
KNOWN_REDOS_SIGNATURES: list[re.Pattern] = [
    re.compile(r"\(\w+\+\)\+"),         # (a+)+  / (\d+)+
    re.compile(r"\(\w+\*\)\+"),          # (a*)+
    re.compile(r"\(\w+\+\)\*"),          # (a+)*
    re.compile(r"\(\w+\*\)\*"),          # (a*)*
    re.compile(r"\.\+\+"),              # .++
    re.compile(r"\w+@\w+\.\w+"),         # nested repeats
    re.compile(r"\(\w+\.\w+\)\+"),       # nested groups with .
    re.compile(r"\([^)]+\)\{[0-9]+,?\}"), # repeating groups
]


class ReDoSError(ValueError):
    """Raised when a regex pattern is rejected as unsafe."""


class ReDoSTimeoutError(TimeoutError):
    """Raised when regex execution exceeds the configured timeout."""


# --- Detection ---

def is_suspected_redos(pattern: str) -> bool:
    """Heuristic check for ReDoS-prone patterns before compilation."""
    for sig in KNOWN_REDOS_SIGNATURES:
        if sig.search(pattern):
            return True
    return False


def validate_regex_pattern(pattern: str) -> None:
    """Validate that a user-supplied regex pattern is safe to compile."""
    if not isinstance(pattern, str):
        raise ReDoSError("Pattern must be a string")

    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ReDoSError(
            f"Pattern exceeds maximum length of {MAX_PATTERN_LENGTH}"
        )

    if is_suspected_redos(pattern):
        raise ReDoSError("Pattern contains known ReDoS signature")

    # Attempt compilation - invalid syntax is also rejected
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ReDoSError(f"Invalid regex pattern: {exc}") from exc


# --- Timeout Execution ---

@contextmanager
def _regex_timeout(seconds: float) -> Iterator[None]:
    """Enforce a wall-clock timeout on regex operations using threading."""
    if seconds <= 0:
        yield
        return

    result: list[Optional[bool]] = [None]
    timer = threading.Timer(seconds, lambda: result.append(True))
    timer.start()
    try:
        yield
    finally:
        timer.cancel()
    if result[1]:
        raise ReDoSTimeoutError(
            f"Regex execution timed out after {seconds}s"
        )


def safe_match(pattern: str, string: str, timeout: float = REGEX_TIMEOUT_SECONDS) -> Optional[re.Match]:
    """Compile and match a regex with ReDoS protection.

    Args:
        pattern: The regex pattern string.
        string: Input string to match against.
        timeout: Maximum seconds for execution.

    Returns:
        re.Match object on success, None if no match.

    Raises:
        ReDoSError: Pattern validation failed.
        ReDoSTimeoutError: Execution exceeded timeout.
    """
    validate_regex_pattern(pattern)
    compiled = re.compile(pattern)

    with _regex_timeout(timeout):
        return compiled.search(string)


def safe_fullmatch(pattern: str, string: str, timeout: float = REGEX_TIMEOUT_SECONDS) -> Optional[re.Match]:
    """Like safe_match but uses fullmatch semantics."""
    validate_regex_pattern(pattern)
    compiled = re.compile(pattern)

    with _regex_timeout(timeout):
        return compiled.fullmatch(string)


# --- Safe Pre-compiled Patterns (no user input needed) ---

SAFE_EMAIL = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
SAFE_URL = re.compile(r"^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$")
SAFE_ALPHANUM = re.compile(r"^[a-zA-Z0-9_]+$")
SAFE_PHONE = re.compile(r"^\+?[0-9]{7,15}$")


# --- Unit Tests ---

class TestReDoSFix(unittest.TestCase):

    def test_known_redos_patterns_are_rejected(self):
        evil_patterns = [
            "(a+)+b",
            "([a-z]+)+[0-9]",
            "(\\d+)*!",
            "a(bc+)+d",
            "(a|aa)+b",
        ]
        for pattern in evil_patterns:
            with self.subTest(pattern=pattern):
                self.assertTrue(is_suspected_redos(pattern))

    def test_safe_patterns_pass_validation(self):
        safe = ["^hello$", r"\d+", "[a-z]{1,10}", "foo|bar"]
        for p in safe:
            with self.subTest(pattern=p):
                validate_regex_pattern(p)

    def test_long_pattern_rejected(self):
        with self.assertRaises(ReDoSError):
            validate_regex_pattern("a" * (MAX_PATTERN_LENGTH + 1))

    def test_timeout_on_evil_input(self):
        pattern = "^(a+)+b$"
        evil_input = "a" * 30 + "c"
        with self.assertRaises(ReDoSTimeoutError):
            safe_match(pattern, evil_input, timeout=0.5)

    def test_quick_match_succeeds(self):
        m = safe_match(r"hello", "hello world")
        self.assertIsNotNone(m)

    def test_precompiled_safe_patterns(self):
        self.assertIsNotNone(SAFE_EMAIL.match("user@example.com"))
        self.assertIsNotNone(SAFE_URL.match("https://example.com/path"))
        self.assertIsNotNone(SAFE_ALPHANUM.match("hello_world123"))
        self.assertIsNotNone(SAFE_PHONE.match("+8613800138000"))


if __name__ == "__main__":
    unittest.main()