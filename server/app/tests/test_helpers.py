"""
BlockSafe Helper Utilities Tests
Test suite for entity extraction and utility functions
"""

import os
import pytest

# Set test environment variables
os.environ["GEMINI_API_KEY"] = "test-gemini-api-key-12345"
os.environ["API_AUTH_KEY"] = "test-auth-key-67890"

from app.utils.helpers import (
    extract_upi_ids,
    extract_bank_accounts,
    extract_urls,
    extract_phone_numbers,
    extract_all_entities,
    count_entities,
    merge_entities,
    sanitize_text,
    ExtractedData
)


# =============================================================================
# UPI EXTRACTION TESTS
# =============================================================================

class TestUPIExtraction:
    """Tests for UPI ID extraction"""

    def test_extracts_standard_upi(self):
        """Should extract standard UPI IDs"""
        text = "Pay to scammer@ybl for immediate resolution."
        result = extract_upi_ids(text)
        assert "scammer@ybl" in result

    def test_extracts_multiple_upi(self):
        """Should extract multiple UPI IDs"""
        text = "Pay to user1@okaxis or user2@paytm"
        result = extract_upi_ids(text)
        assert len(result) >= 2

    def test_ignores_email_addresses(self):
        """Should ignore email addresses"""
        text = "Contact us at support@gmail.com"
        result = extract_upi_ids(text)
        assert "support@gmail.com" not in result

    def test_extracts_upi_variations(self):
        """Should extract various UPI formats"""
        text = "Pay to john@okicici or doe@okhdfcbank"
        result = extract_upi_ids(text)
        assert len(result) >= 1

    def test_empty_text_returns_empty(self):
        """Empty text should return empty list"""
        result = extract_upi_ids("")
        assert result == []


# =============================================================================
# BANK ACCOUNT EXTRACTION TESTS
# =============================================================================

class TestBankAccountExtraction:
    """Tests for bank account extraction"""

    def test_extracts_valid_account(self):
        """Should extract valid bank account numbers"""
        text = "Transfer to account 123456789012"
        result = extract_bank_accounts(text)
        assert "123456789012" in result

    def test_ignores_short_numbers(self):
        """Should ignore numbers less than 9 digits"""
        text = "PIN: 1234, Code: 12345678"
        result = extract_bank_accounts(text)
        assert "1234" not in result
        assert "12345678" not in result

    def test_extracts_long_accounts(self):
        """Should extract 18-digit account numbers"""
        text = "Account: 123456789012345678"
        result = extract_bank_accounts(text)
        assert "123456789012345678" in result

    def test_ignores_phone_numbers(self):
        """Should ignore phone-like numbers"""
        text = "Call 9876543210"
        result = extract_bank_accounts(text)
        # Phone numbers starting with 9,8,7,6 should be filtered
        assert "9876543210" not in result


# =============================================================================
# URL EXTRACTION TESTS
# =============================================================================

class TestURLExtraction:
    """Tests for URL extraction"""

    def test_extracts_http_url(self):
        """Should extract HTTP URLs"""
        text = "Click http://example.com/verify"
        result = extract_urls(text)
        assert "http://example.com/verify" in result

    def test_extracts_https_url(self):
        """Should extract HTTPS URLs"""
        text = "Visit https://secure-bank.com/login"
        result = extract_urls(text)
        assert "https://secure-bank.com/login" in result

    def test_extracts_url_with_params(self):
        """Should extract URLs with query parameters"""
        text = "Go to http://fake.com/page?id=123&ref=scam"
        result = extract_urls(text)
        assert len(result) >= 1

    def test_extracts_multiple_urls(self):
        """Should extract multiple URLs"""
        text = "Visit http://site1.com and https://site2.com"
        result = extract_urls(text)
        assert len(result) == 2

    def test_no_urls_in_plain_text(self):
        """Plain text should return no URLs"""
        text = "This is a normal message without links."
        result = extract_urls(text)
        assert result == []


# =============================================================================
# PHONE NUMBER EXTRACTION TESTS
# =============================================================================

class TestPhoneExtraction:
    """Tests for phone number extraction"""

    def test_extracts_10_digit(self):
        """Should extract 10-digit phone numbers"""
        text = "Call 9876543210 for help"
        result = extract_phone_numbers(text)
        assert any("9876543210" in r for r in result)

    def test_extracts_with_country_code(self):
        """Should extract numbers with +91"""
        text = "Contact +91 9876543210"
        result = extract_phone_numbers(text)
        assert len(result) >= 1

    def test_extracts_formatted_number(self):
        """Should extract formatted numbers"""
        text = "Call 98765-43210 or 9876 543 210"
        result = extract_phone_numbers(text)
        assert len(result) >= 1

    def test_ignores_short_numbers(self):
        """Should ignore numbers less than 10 digits"""
        text = "Code: 12345"
        result = extract_phone_numbers(text)
        assert result == []


# =============================================================================
# EXTRACT ALL ENTITIES TESTS
# =============================================================================

class TestExtractAllEntities:
    """Tests for combined entity extraction"""

    def test_extracts_all_types(self):
        """Should extract all entity types"""
        text = """
        Pay to scammer@ybl
        Account: 123456789012
        Click http://fake.com
        Call 9876543210
        """
        result = extract_all_entities(text)

        assert len(result.upi_ids) >= 1
        assert len(result.bank_accounts) >= 1
        assert len(result.urls) >= 1
        assert len(result.phone_numbers) >= 1

    def test_returns_extracted_data(self):
        """Should return ExtractedData instance"""
        result = extract_all_entities("test message")
        assert isinstance(result, ExtractedData)

    def test_empty_for_clean_text(self):
        """Clean text should return empty entities"""
        result = extract_all_entities("Hello, how are you today?")
        assert count_entities(result) == 0


# =============================================================================
# ENTITY COUNT TESTS
# =============================================================================

class TestEntityCount:
    """Tests for entity counting"""

    def test_counts_all_entities(self):
        """Should count all entity types"""
        data = ExtractedData(
            upi_ids=["a@ybl", "b@paytm"],
            bank_accounts=["123456789"],
            urls=["http://test.com"],
            phone_numbers=["9876543210"]
        )
        assert count_entities(data) == 5

    def test_counts_zero_for_empty(self):
        """Should return 0 for empty data"""
        data = ExtractedData([], [], [], [])
        assert count_entities(data) == 0


# =============================================================================
# MERGE ENTITIES TESTS
# =============================================================================

class TestMergeEntities:
    """Tests for entity merging"""

    def test_merges_entities(self):
        """Should merge two ExtractedData objects"""
        data1 = ExtractedData(
            upi_ids=["a@ybl"],
            bank_accounts=["111111111"],
            urls=[],
            phone_numbers=[]
        )
        data2 = ExtractedData(
            upi_ids=["b@paytm"],
            bank_accounts=["222222222"],
            urls=["http://test.com"],
            phone_numbers=["9876543210"]
        )

        result = merge_entities(data1, data2)

        assert len(result.upi_ids) == 2
        assert len(result.bank_accounts) == 2
        assert len(result.urls) == 1
        assert len(result.phone_numbers) == 1

    def test_deduplicates_entities(self):
        """Should deduplicate when merging"""
        data1 = ExtractedData(
            upi_ids=["same@ybl"],
            bank_accounts=[],
            urls=[],
            phone_numbers=[]
        )
        data2 = ExtractedData(
            upi_ids=["same@ybl"],
            bank_accounts=[],
            urls=[],
            phone_numbers=[]
        )

        result = merge_entities(data1, data2)
        assert len(result.upi_ids) == 1


# =============================================================================
# SANITIZE TEXT TESTS
# =============================================================================

class TestSanitizeText:
    """Tests for text sanitization"""

    def test_removes_control_characters(self):
        """Should remove control characters"""
        text = "Hello\x00World\x1f"
        result = sanitize_text(text)
        assert "\x00" not in result
        assert "\x1f" not in result

    def test_preserves_normal_text(self):
        """Should preserve normal text"""
        text = "Hello World! This is a test."
        result = sanitize_text(text)
        assert result == text

    def test_limits_length(self):
        """Should limit text length"""
        text = "x" * 20000
        result = sanitize_text(text)
        assert len(result) == 10000

    def test_handles_empty_string(self):
        """Should handle empty string"""
        result = sanitize_text("")
        assert result == ""

    def test_handles_none(self):
        """Should handle None-like input"""
        result = sanitize_text(None)
        assert result == ""


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
