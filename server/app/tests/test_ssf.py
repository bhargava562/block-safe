"""
BlockSafe SSF Engine Tests
Test suite for Scam Strategy Fingerprinting
"""

import os
import pytest

# Set test environment variables
os.environ["GEMINI_API_KEY"] = "test-gemini-api-key-12345"
os.environ["API_AUTH_KEY"] = "test-auth-key-67890"

from app.core.ssf_engine import SSFEngine, SSFResult, get_ssf_engine
from app.intelligence.voice_analysis import VoiceSignals


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def ssf_engine():
    """Create SSF engine instance"""
    return SSFEngine()


@pytest.fixture
def scam_message():
    """High-confidence scam message"""
    return """URGENT! Your SBI bank account has been blocked due to suspicious activity.
    This is the FINAL WARNING. Act now before midnight or face legal action.
    Pay Rs. 5000 fine immediately to UPI: scammer@ybl
    Contact us on WhatsApp: 9876543210
    Click here: http://fake-bank.com/verify"""


@pytest.fixture
def legitimate_message():
    """Legitimate message"""
    return "Thank you for your order #12345. Your package will arrive in 3-5 business days."


@pytest.fixture
def voice_signals_urgent():
    """Voice signals indicating urgency"""
    return VoiceSignals(
        speech_rate=210.0,
        urgency_indicators=["fast_speech", "very_fast_speech", "continuous_speech"],
        repetition_detected=True,
        duration_seconds=45.0,
        silence_ratio=0.08
    )


@pytest.fixture
def voice_signals_normal():
    """Normal voice signals"""
    return VoiceSignals(
        speech_rate=120.0,
        urgency_indicators=[],
        repetition_detected=False,
        duration_seconds=30.0,
        silence_ratio=0.25
    )


# =============================================================================
# URGENCY DETECTION TESTS
# =============================================================================

class TestUrgencyDetection:
    """Tests for urgency phrase detection"""

    def test_detects_urgent_keyword(self, ssf_engine):
        """Should detect 'urgent' keyword"""
        result = ssf_engine.analyze("This is urgent! Please respond immediately.")
        assert result.urgency_score > 0
        assert len(result.urgency_phrases) > 0

    def test_detects_immediately(self, ssf_engine):
        """Should detect 'immediately' keyword"""
        result = ssf_engine.analyze("Act immediately to avoid problems.")
        assert any("immediate" in p.lower() for p in result.urgency_phrases)

    def test_detects_deadline_phrases(self, ssf_engine):
        """Should detect deadline phrases"""
        result = ssf_engine.analyze("Complete this within 24 hours or account will be blocked.")
        assert result.urgency_score > 0

    def test_detects_final_warning(self, ssf_engine):
        """Should detect 'final warning' phrase"""
        result = ssf_engine.analyze("This is your FINAL WARNING!")
        assert len(result.urgency_phrases) > 0

    def test_detects_account_blocked(self, ssf_engine):
        """Should detect 'account blocked' phrase"""
        result = ssf_engine.analyze("Your account will be blocked if you don't verify.")
        assert len(result.urgency_phrases) > 0

    def test_low_urgency_for_legitimate(self, ssf_engine, legitimate_message):
        """Legitimate message should have low urgency"""
        result = ssf_engine.analyze(legitimate_message)
        assert result.urgency_score < 0.3

    def test_high_urgency_for_scam(self, ssf_engine, scam_message):
        """Scam message should have high urgency"""
        result = ssf_engine.analyze(scam_message)
        assert result.urgency_score >= 0.3


# =============================================================================
# AUTHORITY CLAIMS TESTS
# =============================================================================

class TestAuthorityClaimsDetection:
    """Tests for authority impersonation detection"""

    def test_detects_rbi(self, ssf_engine):
        """Should detect RBI impersonation"""
        result = ssf_engine.analyze("This is RBI calling about your account.")
        assert "RBI" in result.authority_claims

    def test_detects_police(self, ssf_engine):
        """Should detect police impersonation"""
        result = ssf_engine.analyze("This is the police. You have a pending case.")
        assert "Police" in result.authority_claims

    def test_detects_bank(self, ssf_engine):
        """Should detect bank impersonation"""
        result = ssf_engine.analyze("This is your bank manager from HDFC Bank.")
        assert "Bank" in result.authority_claims

    def test_detects_government(self, ssf_engine):
        """Should detect government impersonation"""
        result = ssf_engine.analyze("This is from the Income Tax department.")
        assert "Government" in result.authority_claims

    def test_detects_tech_company(self, ssf_engine):
        """Should detect tech company impersonation"""
        result = ssf_engine.analyze("This is Microsoft support calling.")
        assert "Tech Company" in result.authority_claims

    def test_multiple_authority_claims(self, ssf_engine):
        """Should detect multiple authority claims"""
        result = ssf_engine.analyze("RBI and police have flagged your bank account.")
        assert len(result.authority_claims) >= 2

    def test_no_authority_in_legitimate(self, ssf_engine, legitimate_message):
        """Legitimate message should have no authority claims"""
        result = ssf_engine.analyze(legitimate_message)
        assert len(result.authority_claims) == 0


# =============================================================================
# PAYMENT ESCALATION TESTS
# =============================================================================

class TestPaymentEscalationDetection:
    """Tests for payment demand detection"""

    def test_detects_upi_payment(self, ssf_engine):
        """Should detect UPI payment demand"""
        result = ssf_engine.analyze("Pay Rs. 5000 to UPI: scammer@ybl immediately.")
        assert result.payment_escalation is True

    def test_detects_bank_transfer(self, ssf_engine):
        """Should detect bank transfer demand"""
        result = ssf_engine.analyze("Transfer the amount to bank account 123456789.")
        assert result.payment_escalation is True

    def test_detects_fine_payment(self, ssf_engine):
        """Should detect fine/penalty demand"""
        result = ssf_engine.analyze("Pay the fine of Rs. 10000 to avoid arrest.")
        assert result.payment_escalation is True

    def test_no_payment_in_legitimate(self, ssf_engine, legitimate_message):
        """Legitimate message should not have payment escalation"""
        result = ssf_engine.analyze(legitimate_message)
        assert result.payment_escalation is False


# =============================================================================
# CHANNEL SWITCH TESTS
# =============================================================================

class TestChannelSwitchDetection:
    """Tests for channel switching intent detection"""

    def test_detects_whatsapp(self, ssf_engine):
        """Should detect WhatsApp redirect"""
        result = ssf_engine.analyze("Contact us on WhatsApp: 9876543210")
        assert result.channel_switch_intent == "WhatsApp"

    def test_detects_telegram(self, ssf_engine):
        """Should detect Telegram redirect"""
        result = ssf_engine.analyze("Join our Telegram channel for updates.")
        assert result.channel_switch_intent == "Telegram"

    def test_detects_call_request(self, ssf_engine):
        """Should detect call request"""
        result = ssf_engine.analyze("Call us at this number for immediate assistance.")
        assert result.channel_switch_intent == "Direct Call"

    def test_detects_website_link(self, ssf_engine):
        """Should detect website redirect"""
        result = ssf_engine.analyze("Click here to visit our website and verify.")
        assert result.channel_switch_intent == "Website"

    def test_no_channel_switch_in_legitimate(self, ssf_engine, legitimate_message):
        """Legitimate message should not have channel switch"""
        result = ssf_engine.analyze(legitimate_message)
        assert result.channel_switch_intent is None


# =============================================================================
# VOICE SIGNAL INTEGRATION TESTS
# =============================================================================

class TestVoiceSignalIntegration:
    """Tests for voice signal integration"""

    def test_voice_signals_increase_urgency(self, ssf_engine, voice_signals_urgent):
        """Urgent voice signals should increase urgency score"""
        text = "Please verify your account details."

        result_without = ssf_engine.analyze(text)
        result_with = ssf_engine.analyze(text, voice_signals_urgent)

        assert result_with.urgency_score > result_without.urgency_score

    def test_normal_voice_minimal_impact(self, ssf_engine, voice_signals_normal):
        """Normal voice signals should have minimal impact"""
        text = "Please verify your account details."

        result_without = ssf_engine.analyze(text)
        result_with = ssf_engine.analyze(text, voice_signals_normal)

        # Difference should be small
        assert abs(result_with.urgency_score - result_without.urgency_score) < 0.2

    def test_fast_speech_adds_urgency(self, ssf_engine):
        """Fast speech rate should add to urgency"""
        text = "Hello"
        voice_fast = VoiceSignals(
            speech_rate=180.0,
            urgency_indicators=["fast_speech"],
            repetition_detected=False,
            duration_seconds=10.0,
            silence_ratio=0.2
        )

        result = ssf_engine.analyze(text, voice_fast)
        assert result.urgency_score > 0


# =============================================================================
# STRATEGY SUMMARY TESTS
# =============================================================================

class TestStrategySummary:
    """Tests for strategy summary generation"""

    def test_generates_summary_for_scam(self, ssf_engine, scam_message):
        """Should generate meaningful summary for scam"""
        result = ssf_engine.analyze(scam_message)
        assert len(result.strategy_summary) > 0
        assert result.strategy_summary != "No significant scam strategy patterns detected"

    def test_generates_default_for_legitimate(self, ssf_engine, legitimate_message):
        """Should generate default summary for legitimate message"""
        result = ssf_engine.analyze(legitimate_message)
        assert "No significant" in result.strategy_summary or result.strategy_summary == ""

    def test_summary_mentions_authority(self, ssf_engine):
        """Summary should mention authority impersonation"""
        result = ssf_engine.analyze("This is RBI calling about your blocked account.")
        assert "RBI" in result.strategy_summary or "Impersonates" in result.strategy_summary

    def test_summary_mentions_urgency(self, ssf_engine):
        """Summary should mention urgency tactics"""
        # Use more urgency phrases to exceed 0.4 threshold
        result = ssf_engine.analyze("URGENT! Act immediately! Final warning! Don't delay! Last chance! Hurry!")
        assert "urgency" in result.strategy_summary.lower() or "pressure" in result.strategy_summary.lower()


# =============================================================================
# EDGE CASES TESTS
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases"""

    def test_empty_text(self, ssf_engine):
        """Should handle empty text"""
        result = ssf_engine.analyze("")
        assert result.urgency_score == 0.0
        assert len(result.authority_claims) == 0
        assert result.payment_escalation is False
        assert result.channel_switch_intent is None

    def test_whitespace_only(self, ssf_engine):
        """Should handle whitespace-only text"""
        result = ssf_engine.analyze("   \n\t  ")
        assert result.urgency_score == 0.0

    def test_urgency_score_bounded(self, ssf_engine):
        """Urgency score should always be 0-1"""
        # Very scammy text
        text = """
        URGENT URGENT URGENT! Act now! Immediately! Don't delay!
        Final warning! Last chance! Limited time! Hurry!
        Your account will be blocked suspended closed frozen!
        Police RBI Bank Government calling! Pay fine now!
        """

        result = ssf_engine.analyze(text)
        assert 0.0 <= result.urgency_score <= 1.0

    def test_case_insensitive(self, ssf_engine):
        """Detection should be case insensitive"""
        result1 = ssf_engine.analyze("URGENT action required")
        result2 = ssf_engine.analyze("urgent action required")

        assert result1.urgency_score == result2.urgency_score

    def test_urgency_phrases_limited(self, ssf_engine):
        """Urgency phrases should be limited to 10"""
        text = "urgent " * 20 + "immediately " * 20
        result = ssf_engine.analyze(text)

        assert len(result.urgency_phrases) <= 10


# =============================================================================
# SSF RESULT DATACLASS TESTS
# =============================================================================

class TestSSFResultDataclass:
    """Tests for SSFResult dataclass"""

    def test_create_ssf_result(self):
        """Should create SSFResult with all fields"""
        result = SSFResult(
            urgency_score=0.75,
            authority_claims=["Bank", "Police"],
            payment_escalation=True,
            channel_switch_intent="WhatsApp",
            urgency_phrases=["urgent", "immediately"],
            strategy_summary="High-pressure scam detected"
        )

        assert result.urgency_score == 0.75
        assert len(result.authority_claims) == 2
        assert result.payment_escalation is True
        assert result.channel_switch_intent == "WhatsApp"
        assert len(result.urgency_phrases) == 2

    def test_ssf_result_defaults(self):
        """SSFResult should handle minimal data"""
        result = SSFResult(
            urgency_score=0.0,
            authority_claims=[],
            payment_escalation=False,
            channel_switch_intent=None,
            urgency_phrases=[],
            strategy_summary=""
        )

        assert result.urgency_score == 0.0
        assert result.authority_claims == []


# =============================================================================
# SINGLETON TESTS
# =============================================================================

class TestSSFEngineSingleton:
    """Tests for SSF engine singleton"""

    def test_get_ssf_engine_returns_instance(self):
        """get_ssf_engine should return an instance"""
        engine = get_ssf_engine()
        assert engine is not None
        assert isinstance(engine, SSFEngine)

    def test_get_ssf_engine_same_instance(self):
        """get_ssf_engine should return same instance"""
        engine1 = get_ssf_engine()
        engine2 = get_ssf_engine()
        assert engine1 is engine2


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
