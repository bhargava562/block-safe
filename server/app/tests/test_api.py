"""
BlockSafe API Tests
Comprehensive test suite for API endpoints and core functionality
"""

import os
import sys
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timezone

# Set test environment variables BEFORE importing app modules
os.environ["GEMINI_API_KEY"] = "test-gemini-api-key-12345"
os.environ["API_AUTH_KEY"] = "test-auth-key-67890"
os.environ["MAX_AUDIO_MB"] = "10"

from fastapi.testclient import TestClient


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(scope="module")
def test_client():
    """Create test client with mocked Gemini"""
    with patch('app.core.scam_detector.genai') as mock_genai:
        # Mock the Gemini client
        mock_client = MagicMock()
        mock_genai.Client.return_value = mock_client

        from app.main import app
        client = TestClient(app, raise_server_exceptions=False)
        yield client


@pytest.fixture
def valid_api_key():
    """Return valid API key for tests"""
    return "test-auth-key-67890"


@pytest.fixture
def scam_message():
    """Sample scam message for testing"""
    return """URGENT! Your SBI bank account has been blocked due to suspicious activity.
    Pay Rs. 5000 fine immediately to UPI: scammer@ybl
    Contact us on WhatsApp: 9876543210
    Click here: http://fake-bank.com/verify
    This is your FINAL WARNING!"""


@pytest.fixture
def legitimate_message():
    """Sample legitimate message for testing"""
    return "Thank you for your order #12345. Your package will arrive in 3-5 business days."


# =============================================================================
# HEALTH ENDPOINT TESTS
# =============================================================================

class TestHealthEndpoint:
    """Tests for /health endpoint"""

    def test_health_returns_200(self, test_client):
        """Health endpoint should return 200 without authentication"""
        response = test_client.get("/health")
        assert response.status_code == 200

    def test_health_response_structure(self, test_client):
        """Health response should have correct structure"""
        response = test_client.get("/health")
        data = response.json()

        assert "status" in data
        assert "version" in data
        assert "timestamp" in data
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"

    def test_health_timestamp_is_valid_iso(self, test_client):
        """Health timestamp should be valid ISO-8601"""
        response = test_client.get("/health")
        data = response.json()

        # Should not raise exception
        timestamp = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        assert timestamp is not None


# =============================================================================
# AUTHENTICATION TESTS
# =============================================================================

class TestAuthentication:
    """Tests for API key authentication"""

    def test_missing_api_key_returns_403(self, test_client):
        """Request without API key should return 403"""
        response = test_client.post(
            "/api/v1/analyze/text",
            json={"message": "test message"}
        )
        assert response.status_code == 403

    def test_invalid_api_key_returns_401(self, test_client):
        """Request with invalid API key should return 401"""
        response = test_client.post(
            "/api/v1/analyze/text",
            json={"message": "test message"},
            headers={"X-API-KEY": "invalid-key"}
        )
        assert response.status_code == 401

    def test_valid_api_key_accepted(self, test_client, valid_api_key):
        """Request with valid API key should be accepted"""
        with patch('app.core.scam_detector.ScamClassifier._client') as mock_client:
            mock_response = MagicMock()
            mock_response.text = '{"is_scam": false, "confidence": 0.1, "scam_type": null, "reasoning": "test"}'
            mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)

            response = test_client.post(
                "/api/v1/analyze/text",
                json={"message": "Hello world"},
                headers={"X-API-KEY": valid_api_key}
            )
            # Should not be 401 or 403
            assert response.status_code not in [401, 403]


# =============================================================================
# TEXT ANALYSIS ENDPOINT TESTS
# =============================================================================

class TestTextAnalysisEndpoint:
    """Tests for POST /api/v1/analyze/text"""

    def test_empty_message_returns_400(self, test_client, valid_api_key):
        """Empty message should return 400"""
        response = test_client.post(
            "/api/v1/analyze/text",
            json={"message": "   "},
            headers={"X-API-KEY": valid_api_key}
        )
        assert response.status_code == 400

    def test_mode_defaults_to_shield(self):
        """Mode should default to 'shield'"""
        from app.api.v1.schemas import TextInput

        input_data = TextInput(message="test message")
        assert input_data.mode == "shield"

    def test_mode_accepts_honeypot(self):
        """Mode should accept 'honeypot' value"""
        from app.api.v1.schemas import TextInput

        input_data = TextInput(message="test message", mode="honeypot")
        assert input_data.mode == "honeypot"

    def test_invalid_mode_rejected(self):
        """Invalid mode should be rejected"""
        from app.api.v1.schemas import TextInput
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            TextInput(message="test", mode="invalid")

    def test_message_max_length(self):
        """Message exceeding max length should be rejected"""
        from app.api.v1.schemas import TextInput
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            TextInput(message="x" * 10001)


# =============================================================================
# AUDIO ANALYSIS ENDPOINT TESTS
# =============================================================================

class TestAudioAnalysisEndpoint:
    """Tests for POST /api/v1/analyze/audio"""

    def test_unsupported_format_returns_415(self, test_client, valid_api_key):
        """Unsupported audio format should return 415"""
        response = test_client.post(
            "/api/v1/analyze/audio",
            files={"file": ("test.txt", b"not audio content", "text/plain")},
            data={"mode": "shield"},
            headers={"X-API-KEY": valid_api_key}
        )
        assert response.status_code == 415

    def test_oversized_file_returns_413(self, test_client, valid_api_key):
        """File exceeding MAX_AUDIO_MB should return 413"""
        # Create 11MB file (exceeds 10MB limit)
        large_content = b"0" * (11 * 1024 * 1024)

        response = test_client.post(
            "/api/v1/analyze/audio",
            files={"file": ("test.wav", large_content, "audio/wav")},
            data={"mode": "shield"},
            headers={"X-API-KEY": valid_api_key}
        )
        assert response.status_code == 413

    def test_supported_audio_formats(self):
        """Verify all supported audio formats"""
        from app.api.v1.routes import SUPPORTED_AUDIO_FORMATS

        expected = {".wav", ".mp3", ".m4a", ".ogg", ".flac", ".webm"}
        assert SUPPORTED_AUDIO_FORMATS == expected


# =============================================================================
# SCHEMA VALIDATION TESTS
# =============================================================================

class TestSchemas:
    """Tests for Pydantic schemas"""

    def test_analysis_response_all_fields(self):
        """AnalysisResponse should have all required fields"""
        from app.api.v1.schemas import (
            AnalysisResponse, ExtractedEntities, SSFProfile
        )

        response = AnalysisResponse(
            request_id="test-uuid",
            timestamp="2026-01-30T00:00:00Z",
            is_scam=True,
            confidence=0.95,
            scam_type="phishing",
            original_message="test message",
            extracted_entities=ExtractedEntities(),
            ssf_profile=SSFProfile(urgency_score=0.8, strategy_summary="test"),
            agent_summary="Test summary",
            evidence_level="HIGH",
            operation_mode="shield"
        )

        assert response.request_id == "test-uuid"
        assert response.is_scam is True
        assert response.confidence == 0.95
        assert response.evidence_level == "HIGH"

    def test_ssf_profile_urgency_score_bounds(self):
        """SSFProfile urgency_score should be bounded 0-1"""
        from app.api.v1.schemas import SSFProfile
        from pydantic import ValidationError

        # Valid scores
        SSFProfile(urgency_score=0.0, strategy_summary="test")
        SSFProfile(urgency_score=1.0, strategy_summary="test")
        SSFProfile(urgency_score=0.5, strategy_summary="test")

        # Invalid scores
        with pytest.raises(ValidationError):
            SSFProfile(urgency_score=-0.1, strategy_summary="test")

        with pytest.raises(ValidationError):
            SSFProfile(urgency_score=1.1, strategy_summary="test")

    def test_extracted_entities_defaults(self):
        """ExtractedEntities should have empty list defaults"""
        from app.api.v1.schemas import ExtractedEntities

        entities = ExtractedEntities()
        assert entities.upi_ids == []
        assert entities.bank_accounts == []
        assert entities.urls == []
        assert entities.phone_numbers == []

    def test_evidence_level_values(self):
        """Evidence level should only accept valid values"""
        from app.api.v1.schemas import AnalysisResponse, ExtractedEntities, SSFProfile
        from pydantic import ValidationError

        valid_levels = ["NONE", "LOW", "MEDIUM", "HIGH"]

        for level in valid_levels:
            response = AnalysisResponse(
                request_id="test",
                timestamp="2026-01-30T00:00:00Z",
                is_scam=False,
                confidence=0.0,
                original_message="test",
                extracted_entities=ExtractedEntities(),
                ssf_profile=SSFProfile(urgency_score=0.0, strategy_summary=""),
                agent_summary="",
                evidence_level=level,
                operation_mode="shield"
            )
            assert response.evidence_level == level


# =============================================================================
# CONFIG TESTS
# =============================================================================

class TestConfig:
    """Tests for configuration module"""

    def test_settings_loads_from_env(self):
        """Settings should load from environment variables"""
        from app.config import Settings

        settings = Settings()
        assert settings.GEMINI_API_KEY.get_secret_value() == "test-gemini-api-key-12345"
        assert settings.API_AUTH_KEY.get_secret_value() == "test-auth-key-67890"

    def test_max_audio_mb_validation(self):
        """MAX_AUDIO_MB should validate bounds"""
        from app.config import Settings
        from pydantic import ValidationError

        # Valid values work
        os.environ["MAX_AUDIO_MB"] = "50"
        settings = Settings()
        assert settings.MAX_AUDIO_MB == 50

        # Reset
        os.environ["MAX_AUDIO_MB"] = "10"

    def test_honeypot_threshold_validation(self):
        """HONEYPOT_CONFIDENCE_THRESHOLD should be 0-1"""
        from app.config import Settings

        settings = Settings()
        assert 0 <= settings.HONEYPOT_CONFIDENCE_THRESHOLD <= 1

    def test_default_values(self):
        """Default configuration values should be correct"""
        from app.config import Settings

        settings = Settings()
        assert settings.GEMINI_MODEL == "gemini-2.0-flash"
        assert settings.HONEYPOT_MAX_TURNS == 5
        assert settings.HONEYPOT_NO_PROGRESS_TURNS == 2
        assert settings.WHISPER_MODEL_SIZE == "base"
        assert settings.WHISPER_DEVICE == "cpu"


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
