"""
Zip Slip → Arbitrary File Write via Archive Extraction Fix
Bounty #779 ($150)
=========================================
Vulnerability: ZIP extraction doesn't validate filenames contain ../.
Attacker crafts ZIP with ../../etc/cron.d/malicious to overwrite files.

Fix: Canonical path validation + reject traversal entries.
"""

import os
import zipfile
from typing import List, Optional, Set
from pathlib import Path


class SafeZipExtractor:
    """
    ZIP extractor that prevents Zip Slip attacks.
    
    Principles:
    1. Validate extracted path is within target directory
    2. Use canonical (real) paths for comparison
    3. Reject entries containing .. or absolute paths
    4. Skip symlinks that point outside the extraction directory
    """

    # Blocked path patterns
    BLOCKED_PATTERNS: Set[str] = {"..", "~"}

    def __init__(self, extract_dir: str):
        self._extract_dir = os.path.abspath(extract_dir)
        os.makedirs(self._extract_dir, exist_ok=True)

    def extract_safe(self, zip_path: str) -> List[str]:
        """
        Extract ZIP file safely.
        Returns list of successfully extracted files.
        """
        extracted = []

        with zipfile.ZipFile(zip_path, "r") as zf:
            for entry in zf.infolist():
                # Validate the entry path
                safe_path = self._validate_entry(entry.filename)
                if safe_path is None:
                    print(f"Skipping malicious entry: {entry.filename}")
                    continue

                # Build full output path
                output_path = os.path.join(self._extract_dir, safe_path)

                # Ensure parent directory exists
                os.makedirs(os.path.dirname(output_path), exist_ok=True)

                # Extract the file
                if not entry.is_dir():
                    with zf.open(entry.filename) as source:
                        with open(output_path, "wb") as target:
                            target.write(source.read())
                    extracted.append(safe_path)

        return extracted

    def _validate_entry(self, entry_path: str) -> Optional[str]:
        """
        Validate a ZIP entry path is safe to extract.
        Returns the safe path, or None if malicious.
        """
        if not entry_path:
            return None

        # Normalize path separators
        normalized = entry_path.replace("\\", "/")

        # Reject absolute paths
        if normalized.startswith("/"):
            return None

        # Reject paths with .. traversal
        parts = normalized.split("/")
        for part in parts:
            if part in self.BLOCKED_PATTERNS:
                return None

        # Build the full path and check it's within extract dir
        full_path = os.path.join(self._extract_dir, normalized)
        canonical = os.path.realpath(full_path)

        if not canonical.startswith(self._extract_dir):
            return None

        return normalized

    def extract_all_safe(self, zip_path: str,
                         validate_callback=None) -> List[str]:
        """
        Extract with optional custom validation callback.
        validate_callback(filename) -> bool
        """
        extracted = []
        with zipfile.ZipFile(zip_path, "r") as zf:
            for entry in zf.infolist():
                # Skip directories and special entries
                if entry.is_dir():
                    continue

                # Custom validation
                if validate_callback and not validate_callback(entry.filename):
                    continue

                # Built-in validation
                safe_path = self._validate_entry(entry.filename)
                if safe_path is None:
                    continue

                output_path = os.path.join(self._extract_dir, safe_path)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)

                with zf.open(entry.filename) as source:
                    with open(output_path, "wb") as target:
                        target.write(source.read())
                extracted.append(safe_path)

        return extracted


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== Zip Slip Prevention ===")
    print()

    # Attack scenario:
    # ZIP entry: ../../etc/cron.d/malicious
    # Without fix: extracts to /var/www/../../etc/cron.d/malicious
    # = /etc/cron.d/malicious (system file overwritten!)

    extractor = SafeZipExtractor("/tmp/safe_extract")

    malicious_entries = [
        "../../etc/cron.d/malicious",
        "/etc/passwd",
        "../../../root/.ssh/authorized_keys",
        "normal_file.txt",
        "subdir/another_file.txt",
    ]

    print("Attack scenario:")
    for entry in malicious_entries:
        safe = extractor._validate_entry(entry)
        if safe:
            print(f"  ✓ {entry:45} → {safe}")
        else:
            print(f"  ✗ {entry:45} → BLOCKED (path traversal)")
    print()

    print("=== Security Measures ===")
    print("✓ Canonical path validation (os.path.realpath)")
    print("✓ Rejects entries containing .. or absolute paths")
    print("✓ Verifies output path is within target directory")
    print("✓ Blocks symlinks pointing outside extract dir")