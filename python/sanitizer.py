"""
Sanitizer module for Python code.

This module provides functions to:
1. Sanitize sensitive data (API keys, passwords, tokens) from Python source code
2. Check if patches are safe to apply (don't overwrite redacted sensitive data)

Used by the file content endpoint and AI service to protect sensitive information.
"""

import re
from typing import Dict, List, Tuple, Optional, Set


# Patterns that span multiple lines and therefore have to be applied to the
# whole content BEFORE the per-line loop below. Prior to 1.46.0 the PEM block
# was only ever applied per-line, which meant pasted private keys never got
# redacted (silent leak). Line count is preserved by padding the replacement
# with the same number of newlines so the per-line redaction tracking that
# follows stays in sync.
MULTILINE_SENSITIVE_PATTERNS = [
    (r'-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----', 'PRIVATE_KEY_REDACTED'),
]

# Common patterns for sensitive data in Python
SENSITIVE_PATTERNS = [
    # API keys and tokens
    (r'["\']([A-Za-z0-9_-]{32,})["\']', 'API_KEY_REDACTED'),  # Generic long alphanumeric strings
    (r'api[_-]?key\s*=\s*["\']([^"\']+)["\']', 'API_KEY_REDACTED'),
    (r'secret[_-]?key\s*=\s*["\']([^"\']+)["\']', 'SECRET_KEY_REDACTED'),
    (r'access[_-]?token\s*=\s*["\']([^"\']+)["\']', 'ACCESS_TOKEN_REDACTED'),
    (r'auth[_-]?token\s*=\s*["\']([^"\']+)["\']', 'AUTH_TOKEN_REDACTED'),
    (r'bearer\s+([A-Za-z0-9._-]{20,})', 'BEARER_TOKEN_REDACTED'),

    # HMAC / JWT / signing secrets (parity with the WordPress connector)
    (r'(hmac[_-]?secret|signing[_-]?key|encryption[_-]?key)\s*=\s*["\']([^"\']{8,})["\']', 'HMAC_SECRET_REDACTED'),
    (r'(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)\s*=\s*["\']([^"\']{8,})["\']', 'JWT_SECRET_REDACTED'),

    # AWS credentials
    (r'aws[_-]?access[_-]?key[_-]?id\s*=\s*["\']([^"\']+)["\']', 'AWS_ACCESS_KEY_REDACTED'),
    (r'aws[_-]?secret[_-]?access[_-]?key\s*=\s*["\']([^"\']+)["\']', 'AWS_SECRET_KEY_REDACTED'),

    # Database credentials
    (r'password\s*=\s*["\']([^"\']+)["\']', 'PASSWORD_REDACTED'),
    (r'db[_-]?password\s*=\s*["\']([^"\']+)["\']', 'DB_PASSWORD_REDACTED'),
    (r'mysql[_-]?password\s*=\s*["\']([^"\']+)["\']', 'MYSQL_PASSWORD_REDACTED'),
    (r'postgres[_-]?password\s*=\s*["\']([^"\']+)["\']', 'POSTGRES_PASSWORD_REDACTED'),

    # SMTP / mail credentials (parity with the WordPress connector)
    (r'(smtp[_-]?password|mail[_-]?password|email[_-]?password)\s*=\s*["\']([^"\']+)["\']', 'SMTP_PASSWORD_REDACTED'),

    # Connection strings with credentials
    (r'(postgresql|mysql|mongodb|redis)://([^:]+):([^@]+)@', r'\1://USERNAME_REDACTED:PASSWORD_REDACTED@'),

    # Environment variable assignments with sensitive names
    (r'os\.environ\[["\']?(API_KEY|SECRET_KEY|PASSWORD|TOKEN)["\']?\]\s*=\s*["\']([^"\']+)["\']', 'SENSITIVE_ENV_REDACTED'),
]

# Additional patterns for common secrets managers
SECRET_MANAGER_PATTERNS = [
    (r'\.get_secret_value\(["\']([^"\']+)["\']\)', 'SECRET_VALUE_REDACTED'),
    (r'secrets\.get\(["\']([^"\']+)["\']\)', 'SECRET_VALUE_REDACTED'),
]


def _apply_multiline_patterns(file_content: str) -> str:
    """Run the whole-content multi-line patterns once, padding the replacement
    with the same number of newlines as the original match so the per-line
    redaction tracking that follows is not thrown off."""
    def _padded_replace(replacement: str):
        def _impl(match: 're.Match') -> str:
            n = match.group(0).count('\n')
            return replacement + ('\n' * n)
        return _impl

    for pattern, replacement in MULTILINE_SENSITIVE_PATTERNS:
        file_content = re.sub(pattern, _padded_replace(replacement), file_content, flags=re.IGNORECASE)
    return file_content


def sanitize_python_code(file_content: str) -> Tuple[str, List[List[int]]]:
    """
    Sanitize Python code and return content with redacted ranges.
    
    This is a simplified wrapper for the file content endpoint.
    
    Args:
        file_content: The raw file content
    
    Returns:
        Tuple of:
        - sanitized_content: The content with sensitive data replaced with placeholders
        - redacted_ranges: List of [start_line, end_line] ranges that were redacted
    """
    sanitized, redacted_lines, _ = sanitize_sensitive_data(file_content)
    
    # Convert list of line numbers to list of ranges
    redacted_ranges = []
    if redacted_lines:
        start = redacted_lines[0]
        end = redacted_lines[0]
        for line in redacted_lines[1:]:
            if line == end + 1:
                end = line
            else:
                redacted_ranges.append([start, end])
                start = line
                end = line
        redacted_ranges.append([start, end])
    
    return sanitized, redacted_ranges


def sanitize_sensitive_data(file_content: str) -> Tuple[str, List[int], Dict[str, any]]:
    """
    Sanitize sensitive data from Python source code.
    
    Args:
        file_content: The raw file content
    
    Returns:
        Tuple of:
        - sanitized_content: The content with sensitive data replaced with placeholders
        - redacted_lines: List of line numbers that were redacted
        - metadata: Dictionary with redaction statistics and warnings
    """
    # Pre-pass: redact multi-line PEM blocks at the whole-content level so the
    # per-line loop below can keep operating one line at a time without missing
    # cross-line secrets.
    file_content = _apply_multiline_patterns(file_content)

    lines = file_content.split('\n')
    redacted_lines = set()
    redaction_count = 0
    redaction_types = {}

    # Lines that the multi-line pre-pass just touched (look for the literal
    # replacement marker).
    for i, line in enumerate(lines):
        if 'PRIVATE_KEY_REDACTED' in line:
            redacted_lines.add(i + 1)
            redaction_count += 1
            redaction_types['PRIVATE_KEY_REDACTED'] = redaction_types.get('PRIVATE_KEY_REDACTED', 0) + 1

    # Apply all sensitive patterns
    for pattern, replacement in SENSITIVE_PATTERNS + SECRET_MANAGER_PATTERNS:
        for i, line in enumerate(lines):
            # Skip comments (basic check)
            if line.strip().startswith('#'):
                continue
            
            # Check if line matches pattern
            if re.search(pattern, line, re.IGNORECASE):
                # Apply redaction
                original_line = line
                line = re.sub(pattern, replacement, line, flags=re.IGNORECASE)
                
                if original_line != line:
                    lines[i] = line
                    redacted_lines.add(i + 1)  # 1-indexed
                    redaction_count += 1
                    
                    # Track redaction type
                    redaction_type = replacement if isinstance(replacement, str) else "PATTERN_REDACTED"
                    redaction_types[redaction_type] = redaction_types.get(redaction_type, 0) + 1
    
    sanitized_content = '\n'.join(lines)
    
    metadata = {
        'redaction_count': redaction_count,
        'redaction_types': redaction_types,
        'has_redactions': redaction_count > 0,
        'redacted_lines_count': len(redacted_lines),
        'warning': 'This file contains sensitive data that has been redacted' if redaction_count > 0 else None
    }
    
    return sanitized_content, sorted(list(redacted_lines)), metadata


def sanitize_log_line_for_ingest(text: str) -> str:
    """
    Best-effort secret redaction on log/trace text before API ingest.
    Uses the same patterns as file-content sanitization; heuristic only (not exhaustive).
    """
    content, _, _ = sanitize_sensitive_data(text)
    return content


def is_patch_safe_to_apply(patch_content: str, redacted_lines: List[int], file_path: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a patch is safe to apply (doesn't modify redacted lines).
    
    Args:
        patch_content: The unified diff patch content
        redacted_lines: List of line numbers that were redacted
        file_path: Path to the file being patched
    
    Returns:
        Tuple of:
        - is_safe: Boolean indicating if patch is safe
        - reason: If not safe, explanation of why
    """
    if not redacted_lines:
        return True, None
    
    # Parse unified diff format to extract modified lines
    modified_lines = set()
    
    # Unified diff format:
    # @@ -start,count +start,count @@
    # Lines starting with '-' are removed
    # Lines starting with '+' are added
    # Lines starting with ' ' are context
    
    current_line = None
    for line in patch_content.split('\n'):
        # Parse hunk header
        if line.startswith('@@'):
            # Extract starting line number for changes
            match = re.search(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
            if match:
                current_line = int(match.group(3))  # Starting line in new file
        elif current_line is not None:
            if line.startswith('+'):
                modified_lines.add(current_line)
                current_line += 1
            elif line.startswith('-'):
                # Deleted line doesn't increment current_line
                pass
            elif line.startswith(' '):
                # Context line
                current_line += 1
    
    # Check if any modified lines overlap with redacted lines
    overlapping_lines = modified_lines.intersection(set(redacted_lines))
    
    if overlapping_lines:
        return False, f"Patch attempts to modify redacted sensitive data on lines: {sorted(list(overlapping_lines))}"
    
    return True, None


def detect_sensitive_patterns(code: str) -> Dict[str, List[Dict[str, any]]]:
    """
    Detect sensitive patterns in code without redacting (for analysis).
    
    Args:
        code: The code to analyze
    
    Returns:
        Dictionary mapping pattern types to lists of matches with line numbers
    """
    detections = {}
    lines = code.split('\n')
    
    for pattern, redaction_type in SENSITIVE_PATTERNS + SECRET_MANAGER_PATTERNS:
        matches = []
        for i, line in enumerate(lines):
            if re.search(pattern, line, re.IGNORECASE):
                matches.append({
                    'line_number': i + 1,
                    'line_content': line.strip(),
                    'pattern_type': redaction_type
                })
        
        if matches:
            detections[redaction_type] = matches
    
    return detections


def mask_sensitive_value(value: str, reveal_chars: int = 4) -> str:
    """
    Mask a sensitive value, revealing only the last N characters.
    
    Args:
        value: The sensitive value to mask
        reveal_chars: Number of characters to reveal at the end
    
    Returns:
        Masked value (e.g., "****abcd")
    """
    if len(value) <= reveal_chars:
        return '*' * len(value)
    
    return '*' * (len(value) - reveal_chars) + value[-reveal_chars:]


def get_redaction_summary(metadata: Dict[str, any]) -> str:
    """
    Generate a human-readable summary of redactions.
    
    Args:
        metadata: Metadata from sanitize_sensitive_data()
    
    Returns:
        Human-readable summary string
    """
    if not metadata.get('has_redactions'):
        return "No sensitive data detected in this file."
    
    count = metadata.get('redaction_count', 0)
    lines_count = metadata.get('redacted_lines_count', 0)
    types = metadata.get('redaction_types', {})
    
    summary_parts = [
        f"Redacted {count} sensitive value(s) across {lines_count} line(s):",
    ]
    
    for redaction_type, type_count in types.items():
        summary_parts.append(f"  - {redaction_type}: {type_count} occurrence(s)")
    
    return '\n'.join(summary_parts)

