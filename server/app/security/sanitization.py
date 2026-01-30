"""
BlockSafe Input Sanitization
Security utilities for input validation and sanitization
"""

import re
import html
from typing import Optional


def sanitize_text_input(text: str, max_length: int = 10000) -> str:
    """
    Sanitize text input to prevent injection attacks.

    Args:
        text: Raw input text
        max_length: Maximum allowed length

    Returns:
        Sanitized text
    """
    if not text:
        return ""

    # Remove null bytes and control characters (except newlines/tabs)
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)

    # Limit length
    sanitized = sanitized[:max_length]

    return sanitized


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal.

    Args:
        filename: Raw filename

    Returns:
        Safe filename
    """
    if not filename:
        return "unknown"

    # Remove path components
    filename = filename.replace("\\", "/")
    filename = filename.split("/")[-1]

    # Remove potentially dangerous characters
    filename = re.sub(r'[<>:"|?*]', '', filename)

    # Limit length
    return filename[:255]


def escape_html(text: str) -> str:
    """
    Escape HTML special characters.

    Args:
        text: Raw text

    Returns:
        HTML-escaped text
    """
    return html.escape(text)


def validate_json_string(text: str) -> bool:
    """
    Validate that a string doesn't contain JSON injection attempts.

    Args:
        text: Text to validate

    Returns:
        True if safe, False if suspicious
    """
    # Check for common JSON injection patterns
    suspicious_patterns = [
        r'\}\s*\{',  # Attempting to close and open new object
        r'\]\s*\[',  # Attempting to close and open new array
        r'\\u0000',  # Null byte in unicode
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, text):
            return False

    return True


def strip_sensitive_data(text: str) -> str:
    """
    Remove potentially sensitive data patterns from text for logging.

    Args:
        text: Text that may contain sensitive data

    Returns:
        Text with sensitive data masked
    """
    # Mask potential credit card numbers
    text = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[CARD]', text)

    # Mask potential SSN/Aadhaar-like patterns
    text = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[ID]', text)

    # Mask potential passwords
    text = re.sub(r'(?i)(password|pwd|pass)\s*[=:]\s*\S+', r'\1=[REDACTED]', text)

    return text
