"""
BlockSafe Helper Utilities
Entity extraction via regex patterns
"""

import re
from typing import Optional
from dataclasses import dataclass


@dataclass
class ExtractedData:
    """Container for extracted entities"""
    upi_ids: list[str]
    bank_accounts: list[str]
    urls: list[str]
    phone_numbers: list[str]


# === Regex Patterns ===

# UPI ID pattern: username@bankcode (e.g., john@okaxis, pay@ybl)
UPI_PATTERN = re.compile(
    r'\b([a-zA-Z0-9._-]+@[a-zA-Z]{2,}(?:upi|pay|paytm|okaxis|okhdfcbank|okicici|ybl|apl|ibl)?)\b',
    re.IGNORECASE
)

# Bank account numbers: 9-18 digits
BANK_ACCOUNT_PATTERN = re.compile(r'\b(\d{9,18})\b')

# URL pattern: http/https links
URL_PATTERN = re.compile(
    r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\-.?=&#%]*',
    re.IGNORECASE
)

# Phone number patterns (Indian format)
PHONE_PATTERN = re.compile(
    r'(?:\+91[\s-]?)?(?:\d{10}|\d{5}[\s-]\d{5}|\d{4}[\s-]\d{3}[\s-]\d{3})',
    re.IGNORECASE
)

# IFSC code pattern
IFSC_PATTERN = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', re.IGNORECASE)


def extract_upi_ids(text: str) -> list[str]:
    """Extract UPI IDs from text"""
    matches = UPI_PATTERN.findall(text)
    # Filter out email-like patterns
    upi_ids = [
        m for m in matches
        if not any(domain in m.lower() for domain in ['gmail', 'yahoo', 'hotmail', 'outlook', '.com', '.in', '.org'])
    ]
    return list(set(upi_ids))


def extract_bank_accounts(text: str) -> list[str]:
    """Extract potential bank account numbers from text"""
    matches = BANK_ACCOUNT_PATTERN.findall(text)
    # Filter to valid ranges (avoid phone numbers, PINs, etc.)
    accounts = [
        m for m in matches
        if len(m) >= 9 and not m.startswith('0') and not is_likely_phone(m)
    ]
    return list(set(accounts))


def extract_urls(text: str) -> list[str]:
    """Extract URLs from text"""
    matches = URL_PATTERN.findall(text)
    return list(set(matches))


def extract_phone_numbers(text: str) -> list[str]:
    """Extract phone numbers from text"""
    matches = PHONE_PATTERN.findall(text)
    # Normalize phone numbers
    normalized = []
    for phone in matches:
        clean = re.sub(r'[\s-]', '', phone)
        if len(clean) >= 10:
            normalized.append(clean)
    return list(set(normalized))


def is_likely_phone(number: str) -> bool:
    """Check if a number is likely a phone number"""
    clean = re.sub(r'[\s-]', '', number)
    return len(clean) == 10 and clean.startswith(('6', '7', '8', '9'))


def extract_all_entities(text: str) -> ExtractedData:
    """Extract all entity types from text"""
    return ExtractedData(
        upi_ids=extract_upi_ids(text),
        bank_accounts=extract_bank_accounts(text),
        urls=extract_urls(text),
        phone_numbers=extract_phone_numbers(text)
    )


def count_entities(data: ExtractedData) -> int:
    """Count total entities extracted"""
    return (
        len(data.upi_ids) +
        len(data.bank_accounts) +
        len(data.urls) +
        len(data.phone_numbers)
    )


def merge_entities(base: ExtractedData, new: ExtractedData) -> ExtractedData:
    """Merge two ExtractedData objects, deduplicating"""
    return ExtractedData(
        upi_ids=list(set(base.upi_ids + new.upi_ids)),
        bank_accounts=list(set(base.bank_accounts + new.bank_accounts)),
        urls=list(set(base.urls + new.urls)),
        phone_numbers=list(set(base.phone_numbers + new.phone_numbers))
    )


def sanitize_text(text: str) -> str:
    """Sanitize text input to prevent injection attacks"""
    if not text:
        return ""
    # Remove control characters except newlines and tabs
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    # Limit length
    return sanitized[:10000]
