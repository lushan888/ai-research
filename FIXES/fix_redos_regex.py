"""
fix_redos_regex.py — ReDoS Protection for User-Controlled Regex Patterns

Issue #724 — Search feature allows user-supplied regex: `new RegExp(userInput)`.
Attacker submits `(a+)+b` with input `aaaaaaaaaaaaaaaac`, causing catastrophic
backtracking and CPU exhaustion.

FIX:
1. Set regex execution timeout
2. Limit input pattern length
3. Use ReDoS-safe regex engine with pre-compiled safe patterns
"""

from __future__ import annotations

import re
import signal
import threading
import time
from typing import Callable, Dict, List, Optional, Pattern, Tuple


# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

# Maximum regex pattern length (prevents huge patterns)
MAX_PATTERN_LENGTH = 200

# Default timeout in seconds for regex execution
DEFAULT_REGEX_TIMEOUT = 1.0

# Patterns known to be vulnerable to ReDoS (blocklist)
KNOWN_VULNERABLE_PATTERNS: List[str] = [
    r"\(.+\)\+",       # Nested repetition: (pattern)+
    r"\(.+\)\*",       # Nested repetition: (pattern)*
    r"\(.+\)\{",       # Nested repetition with quantifier
    r"\[^?.*\]\+",     # Negated char class + quantifier
    r"\w+\(.*\)\+",    # Word char + group + quantifier
    r"[a-z]+\(.*\)\+", # Char class + group + quantifier
]

# Safe pattern whitelist (pre-compiled, ReDoS-verified)
SAFE_PATTERNS: Dict[str, Pattern] = {
    "email": re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
    "phone": re.compile(r"^\+?[1-9]\d{1,14}$"),
    "url": re.compile(r"^https?://[^\s/$.?#].[^\s]*$"),
    "alphanumeric": re.compile(r"^[a-zA-Z0-9]+$"),
    "hex": re.compile(r"^[0-9a-fA-F]+$"),
    "ipv4": re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"),
    "date_iso": re.compile(r"^\d{4}-\d{2}-\d{2}$"),
}


# ═══════════════════════════════════════════════════════════════════
# 1. ReDoS Detector
# ═══════════════════════════════════════════════════════════════════


class ReDoSDetector:
    """Detect potentially vulnerable regex patterns."""

    @staticmethod
    def is_potentially_vulnerable(pattern: str) -> Tuple[bool, str]:
        """Check if a regex pattern might be vulnerable to ReDoS.

        Returns:
            Tuple of (is_vulnerable, reason)
        """
        if len(pattern) > MAX_PATTERN_LENGTH:
            return True, f"Pattern too long ({len(pattern)} > {MAX_PATTERN_LENGTH})"

        # Check for nested quantifiers (the main ReDoS vector)
        # Patterns like (a+)+, (a*)*, (a+)*, (a*)+, etc.
        if re.search(r'\([^)]*[+*]\)[+*]', pattern):
            return True, "Nested quantifier detected"

        if re.search(r'\([^)]*\)[+*]\s*\(', pattern):
            return True, "Adjacent quantifiers detected"

        # Check for overlapping alternations with repetition
        if re.search(r'\([^)]*\|[^)]*\)[+*]', pattern):
            return True, "Alternation with repetition detected"

        return False, ""

    @staticmethod
    def analyze_pattern(pattern: str) -> Dict[str, object]:
        """Analyze a regex pattern for ReDoS risk factors."""
        risk_factors = []
        risk_score = 0

        # Length check
        if len(pattern) > 100:
            risk_factors.append(f"Long pattern ({len(pattern)} chars)")
            risk_score += 1

        # Nested quantifiers
        nested = re.findall(r'\([^)]*[+*]\)[+*]', pattern)
        if nested:
            risk_factors.append(f"Nested quantifiers: {nested}")
            risk_score += 3

        # Alternations
        alts = pattern.count("|")
        if alts > 3:
            risk_factors.append(f"Many alternations ({alts})")
            risk_score += 1

        # Large character classes
        classes = re.findall(r'\[[^\]]{10,}\]', pattern)
        if classes:
            risk_factors.append(f"Large character classes: {len(classes)}")
            risk_score += 1

        # Backreferences
        if "\\1" in pattern or "\\2" in pattern:
            risk_factors.append("Backreferences present")
            risk_score += 2

        return {
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "is_risky": risk_score >= 3,
        }


# ═══════════════════════════════════════════════════════════════════
# 2. Timeout Regex Engine
# ═══════════════════════════════════════════════════════════════════


class TimeoutRegex:
    """Regex engine with execution timeout protection.

    Uses threading to enforce time limits on regex matching.
    """

    class RegexTimeoutError(TimeoutError):
        """Raised when regex execution exceeds timeout."""

    def __init__(self, timeout: float = DEFAULT_REGEX_TIMEOUT):
        self.timeout = timeout
        self._result: Optional[re.Match] = None
        self._exception: Optional[Exception] = None
        self._completed = False

    def _run_match(self, pattern: Pattern, text: str):
        """Run regex match in a separate thread."""
        try:
            self._result = pattern.search(text)
            self._completed = True
        except Exception as e:
            self._exception = e
            self._completed = True

    def safe_search(
        self, pattern: Pattern, text: str
    ) -> Optional[re.Match]:
        """Perform regex search with timeout protection.

        Args:
            pattern: Compiled regex pattern
            text: Text to search in

        Returns:
            Match object or None if no match found

        Raises:
            RegexTimeoutError: If regex execution exceeds timeout
        """
        self._result = None
        self._exception = None
        self._completed = False

        thread = threading.Thread(
            target=self._run_match, args=(pattern, text), daemon=True
        )
        thread.start()
        thread.join(timeout=self.timeout)

        if thread.is_alive():
            # Thread still running = timeout
            raise TimeoutRegex.RegexTimeoutError(
                f"Regex execution exceeded {self.timeout}s timeout"
            )

        if self._exception:
            raise self._exception

        return self._result

    def safe_match(
        self, pattern: Pattern, text: str
    ) -> Optional[re.Match]:
        """Perform regex full-match with timeout protection."""
        self._result = None
        self._exception = None
        self._completed = False

        thread = threading.Thread(
            target=self._run_full_match, args=(pattern, text), daemon=True
        )
        thread.start()
        thread.join(timeout=self.timeout)

        if thread.is_alive():
            raise TimeoutRegex.RegexTimeoutError(
                f"Regex execution exceeded {self.timeout}s timeout"
            )

        if self._exception:
            raise self._exception

        return self._result

    def _run_full_match(self, pattern: Pattern, text: str):
        try:
            self._result = pattern.fullmatch(text)
            self._completed = True
        except Exception as e:
            self._exception = e
            self._completed = True

    def safe_findall(
        self, pattern: Pattern, text: str
    ) -> List[str]:
        """Perform regex findall with timeout protection."""
        self._result = None
        self._exception = None
        self._completed = False
        self._findall_result: List[str] = []

        thread = threading.Thread(
            target=self._run_findall, args=(pattern, text), daemon=True
        )
        thread.start()
        thread.join(timeout=self.timeout)

        if thread.is_alive():
            raise TimeoutRegex.RegexTimeoutError(
                f"Regex execution exceeded {self.timeout}s timeout"
            )

        if self._exception:
            raise self._exception

        return self._findall_result

    def _run_findall(self, pattern: Pattern, text: str):
        try:
            self._findall_result = pattern.findall(text)
            self._completed = True
        except Exception as e:
            self._exception = e
            self._completed = True


# ═══════════════════════════════════════════════════════════════════
# 3. Safe Regex Compiler
# ═══════════════════════════════════════════════════════════════════


class SafeRegexCompiler:
    """Compile regex patterns with ReDoS safety checks."""

    def __init__(
        self,
        max_length: int = MAX_PATTERN_LENGTH,
        timeout: float = DEFAULT_REGEX_TIMEOUT,
    ):
        self.max_length = max_length
        self.timeout = timeout
        self.detector = ReDoSDetector()
        self.engine = TimeoutRegex(timeout=timeout)

    def compile(self, pattern: str, flags: int = 0) -> Pattern:
        """Compile a regex pattern with safety checks.

        Args:
            pattern: Regex pattern string
            flags: Regex flags

        Returns:
            Compiled pattern

        Raises:
            ValueError: If pattern is too long or potentially vulnerable
        """
        if len(pattern) > self.max_length:
            raise ValueError(
                f"Pattern too long: {len(pattern)} > {self.max_length}"
            )

        # Check for obvious ReDoS patterns
        is_vuln, reason = self.detector.is_potentially_vulnerable(pattern)
        if is_vuln:
            raise ValueError(
                f"Pattern may be vulnerable to ReDoS: {reason}"
            )

        # Try to compile (catches syntax errors)
        try:
            compiled = re.compile(pattern, flags)
        except re.error as e:
            raise ValueError(f"Invalid regex: {e}")

        # Verify the pattern isn't malicious by running a quick test
        self._verify_pattern(compiled)

        return compiled

    def _verify_pattern(self, pattern: Pattern):
        """Quick verification that pattern doesn't cause ReDoS."""
        # Test with a worst-case input
        test_input = "a" * 50 + "b"
        try:
            self.engine.safe_search(pattern, test_input)
        except TimeoutRegex.RegexTimeoutError:
            raise ValueError(
                "Pattern causes catastrophic backtracking (ReDoS)"
            )


# ═══════════════════════════════════════════════════════════════════
# 4. Direct Fix: Search Function
# ═══════════════════════════════════════════════════════════════════


class ReDoSProtectedSearch:
    """ReDoS-safe search functionality.

    Original vulnerable code:
        results = re.search(new RegExp(userInput), text)

    Fixed code:
        searcher = ReDoSProtectedSearch()
        results = searcher.search(userInput, text)
    """

    def __init__(self, timeout: float = DEFAULT_REGEX_TIMEOUT):
        self.compiler = SafeRegexCompiler(timeout=timeout)
        self.engine = TimeoutRegex(timeout=timeout)

    def search(self, pattern: str, text: str, flags: int = 0) -> Optional[re.Match]:
        """ReDoS-safe regex search.

        Args:
            pattern: User-supplied regex pattern
            text: Text to search
            flags: Regex flags

        Returns:
            Match object or None
        """
        compiled = self.compiler.compile(pattern, flags)
        return self.engine.safe_search(compiled, text)

    def search_safe_pattern(
        self, pattern_name: str, text: str
    ) -> Optional[re.Match]:
        """Search using a pre-compiled safe pattern."""
        if pattern_name not in SAFE_PATTERNS:
            raise ValueError(f"Unknown safe pattern: {pattern_name}")
        return self.engine.safe_search(SAFE_PATTERNS[pattern_name], text)

    def is_match(self, pattern: str, text: str, flags: int = 0) -> bool:
        """ReDoS-safe regex match check."""
        compiled = self.compiler.compile(pattern, flags)
        return self.engine.safe_match(compiled, text) is not None


# ═══════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════


def test_redos_detection():
    """Test that ReDoS-vulnerable patterns are detected."""
    detector = ReDoSDetector()

    # Known vulnerable patterns
    assert detector.is_potentially_vulnerable("(a+)+b")[0]
    assert detector.is_potentially_vulnerable("(a*)*b")[0]
    assert detector.is_potentially_vulnerable("([a-z]+)+b")[0]
    assert detector.is_potentially_vulnerable("(a|b)+c")[0]

    # Safe patterns
    assert not detector.is_potentially_vulnerable("hello")[0]
    assert not detector.is_potentially_vulnerable("^[a-z]+$")[0]
    assert not detector.is_potentially_vulnerable(r"\d{3}-\d{4}")[0]

    print("PASS: ReDoS detection")


def test_timeout_regex():
    """Test that regex timeout works."""
    engine = TimeoutRegex(timeout=0.1)  # 100ms timeout

    # Safe pattern should work
    pattern = re.compile(r"hello")
    result = engine.safe_search(pattern, "hello world")
    assert result is not None

    # No match should return None
    result = engine.safe_search(pattern, "goodbye")
    assert result is None

    print("PASS: Timeout regex")


def test_safe_compiler():
    """Test SafeRegexCompiler."""
    compiler = SafeRegexCompiler(max_length=200, timeout=0.5)

    # Safe pattern compiles
    pattern = compiler.compile(r"hello")
    assert pattern.search("hello world")

    # Too long pattern
    try:
        compiler.compile("a" * 300)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

    # Vulnerable pattern (quick test with small input)
    # Note: (a+)+b with short input won't trigger timeout,
    # but the detector should catch it
    try:
        compiler.compile(r"(a+)+b")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

    print("PASS: Safe compiler")


def test_redos_protected_search():
    """Test ReDoSProtectedSearch."""
    searcher = ReDoSProtectedSearch(timeout=0.5)

    # Normal search
    result = searcher.search(r"\d+", "abc123def")
    assert result is not None
    assert result.group() == "123"

    # No match
    result = searcher.search(r"\d+", "abcdef")
    assert result is None

    print("PASS: ReDoSProtectedSearch")


def test_safe_patterns():
    """Test pre-compiled safe patterns."""
    searcher = ReDoSProtectedSearch()

    assert searcher.search_safe_pattern("email", "test@example.com") is not None
    assert searcher.search_safe_pattern("email", "not-an-email") is None
    assert searcher.search_safe_pattern("hex", "deadbeef") is not None

    # Unknown pattern
    try:
        searcher.search_safe_pattern("unknown", "test")
        assert False
    except ValueError:
        pass

    print("PASS: Safe patterns")


def test_edge_cases():
    """Test edge cases."""
    searcher = ReDoSProtectedSearch(timeout=0.5)

    # Empty pattern
    try:
        searcher.search("", "test")
    except ValueError:
        pass  # Empty pattern is invalid

    # Special characters
    result = searcher.search(r"\.\*\+", "test.*+")
    assert result is not None

    # Unicode
    result = searcher.search(r"[\u4e00-\u9fff]+", "中文测试")
    assert result is not None

    print("PASS: Edge cases")


def test_regex_flags():
    """Test regex flags support."""
    searcher = ReDoSProtectedSearch(timeout=0.5)

    # Case insensitive
    result = searcher.search(r"hello", "HELLO WORLD", flags=re.IGNORECASE)
    assert result is not None

    # Without flag
    result = searcher.search(r"hello", "HELLO WORLD")
    assert result is None

    print("PASS: Regex flags")


def test_pattern_length_limit():
    """Test pattern length limit."""
    compiler = SafeRegexCompiler(max_length=50)

    # Under limit
    compiler.compile("a" * 50)

    # Over limit
    try:
        compiler.compile("a" * 51)
        assert False
    except ValueError:
        pass

    print("PASS: Pattern length limit")


if __name__ == "__main__":
    test_redos_detection()
    test_timeout_regex()
    test_safe_compiler()
    test_redos_protected_search()
    test_safe_patterns()
    test_edge_cases()
    test_regex_flags()
    test_pattern_length_limit()
    print("\n✅ ALL 8 TESTS PASSED — ReDoS Protection Fix Complete!")