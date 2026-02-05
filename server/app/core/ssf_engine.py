"""
BlockSafe Scam Strategy Fingerprint (SSF) Engine
Behavioral pattern analysis for ecosystem-wide learning
"""

import re
from typing import Optional, List
from dataclasses import dataclass


from app.config import get_settings
from app.intelligence.voice_analysis import VoiceSignals
from app.utils.logger import logger


@dataclass
class SSFResult:
    """Scam Strategy Fingerprint result"""
    urgency_score: float
    authority_claims: List[str]
    payment_escalation: bool
    channel_switch_intent: Optional[str]
    urgency_phrases: List[str]
    strategy_summary: str


class SSFEngine:
    """
    Scam Strategy Fingerprinting Engine.
    Analyzes behavioral patterns to create portable intelligence vectors.

    Key signals:
    - Urgency phrases and tactics
    - Authority figure impersonation
    - Payment escalation patterns
    - Channel-switching intent
    """

    # Urgency phrase patterns
    URGENCY_PATTERNS = [
        r'\b(immediate(?:ly)?|urgent(?:ly)?|right now|act now|don\'t delay)\b',
        r'\b(limited time|expires? today|last chance|final warning)\b',
        r'\b(within \d+ (?:hour|minute|day)s?|before midnight)\b',
        r'\b(hurry|quick(?:ly)?|fast|asap|emergency)\b',
        r'\b(account (?:will be |is being )?(?:blocked|suspended|closed|frozen))\b',
        r'\b(legal action|police|arrest|court|lawsuit)\b',
        r'\b(verify now|confirm now|update now|click now)\b',
    ]

    # Authority patterns
    AUTHORITY_PATTERNS = {
        'RBI': r'\b(rbi|reserve bank|central bank)\b',
        'Police': r'\b(police|cop|officer|crime branch|cyber (?:cell|crime))\b',
        'Bank': r'\b(bank (?:manager|officer|executive)|(?:hdfc|icici|sbi|axis) bank)\b',
        'Government': r'\b(government|ministry|income tax|it department|gst)\b',
        'Telecom': r'\b(airtel|jio|vodafone|bsnl|telecom|trai)\b',
        'Tech Company': r'\b(microsoft|google|apple|amazon|facebook|meta)\b',
        'Customs': r'\b(customs|import|export|parcel|courier)\b',
    }

    # Channel switch patterns
    CHANNEL_PATTERNS = {
        'WhatsApp': r'\b(whatsapp|wa\.me|whats app)\b',
        'Telegram': r'\b(telegram|t\.me)\b',
        'Direct Call': r'\b(call (?:me|us|this number)|phone|dial)\b',
        'Email': r'\b(email|mail us|send mail)\b',
        'Website': r'\b(visit|go to|click|website|link)\b',
    }

    # Payment keywords
    PAYMENT_PATTERNS = [
        r'\b(pay(?:ment)?|transfer|send money|deposit)\b',
        r'\b(upi|gpay|paytm|phonepe|bhim)\b',
        r'\b(bank account|account number|ifsc)\b',
        r'\b(fee|charge|fine|penalty|tax)\b',
        r'\b(refund|cashback|prize|reward|lottery)\b',
    ]

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficiency"""
        self._urgency_compiled = [
            re.compile(p, re.IGNORECASE) for p in self.URGENCY_PATTERNS
        ]
        self._authority_compiled = {
            k: re.compile(v, re.IGNORECASE)
            for k, v in self.AUTHORITY_PATTERNS.items()
        }
        self._channel_compiled = {
            k: re.compile(v, re.IGNORECASE)
            for k, v in self.CHANNEL_PATTERNS.items()
        }
        self._payment_compiled = [
            re.compile(p, re.IGNORECASE) for p in self.PAYMENT_PATTERNS
        ]

    def analyze(
        self,
        text: str,
        voice_signals: Optional[VoiceSignals] = None
    ) -> SSFResult:
        """
        Analyze text (and optionally voice signals) to generate SSF profile.

        Args:
            text: Message text to analyze
            voice_signals: Optional voice analysis results

        Returns:
            SSFResult with fingerprint data
        """
        # Detect urgency phrases
        urgency_phrases = self._detect_urgency_phrases(text)

        # Calculate urgency score (0-1)
        urgency_score = self._calculate_urgency_score(
            urgency_phrases, voice_signals
        )

        # Detect authority claims
        authority_claims = self._detect_authority_claims(text)

        # Detect payment escalation indicators
        payment_escalation = self._detect_payment_escalation(text)

        # Detect channel switch intent
        channel_switch_intent = self._detect_channel_switch(text)

        # Generate strategy summary
        strategy_summary = self._generate_summary(
            urgency_score=urgency_score,
            authority_claims=authority_claims,
            payment_escalation=payment_escalation,
            channel_switch_intent=channel_switch_intent,
            urgency_phrases=urgency_phrases
        )

        return SSFResult(
            urgency_score=round(urgency_score, 2),
            authority_claims=authority_claims,
            payment_escalation=payment_escalation,
            channel_switch_intent=channel_switch_intent,
            urgency_phrases=urgency_phrases[:10],  # Limit to top 10
            strategy_summary=strategy_summary
        )

    def _detect_urgency_phrases(self, text: str) -> List[str]:
        """Extract urgency phrases from text"""
        phrases = []
        for pattern in self._urgency_compiled:
            matches = pattern.findall(text)
            phrases.extend(matches)
        return list(set(phrases))

    def _calculate_urgency_score(
        self,
        phrases: List[str],
        voice_signals: Optional[VoiceSignals]
    ) -> float:
        """
        Calculate overall urgency score (0-1).
        Combines text and voice signals.
        """
        # Base score from phrase count
        phrase_score = min(len(phrases) / 5, 1.0) * 0.6

        # Voice signal contribution
        voice_score = 0.0
        if voice_signals:
            if voice_signals.speech_rate > 160:
                voice_score += 0.15
            if voice_signals.speech_rate > 200:
                voice_score += 0.1
            if voice_signals.repetition_detected:
                voice_score += 0.1
            if 'continuous_speech' in voice_signals.urgency_indicators:
                voice_score += 0.05

        return min(phrase_score + voice_score, 1.0)

    def _detect_authority_claims(self, text: str) -> List[str]:
        """Detect claimed authority figures"""
        claims = []
        for authority, pattern in self._authority_compiled.items():
            if pattern.search(text):
                claims.append(authority)
        return claims

    def _detect_payment_escalation(self, text: str) -> bool:
        """Detect if payment demands are present"""
        payment_count = 0
        for pattern in self._payment_compiled:
            if pattern.search(text):
                payment_count += 1
        # Escalation if multiple payment indicators
        return payment_count >= 2

    def _detect_channel_switch(self, text: str) -> Optional[str]:
        """Detect intent to switch communication channels"""
        for channel, pattern in self._channel_compiled.items():
            if pattern.search(text):
                return channel
        return None

    def _generate_summary(
        self,
        urgency_score: float,
        authority_claims: List[str],
        payment_escalation: bool,
        channel_switch_intent: Optional[str],
        urgency_phrases: List[str]
    ) -> str:
        """Generate human-readable strategy summary"""
        parts = []

        # Urgency assessment
        if urgency_score > 0.7:
            parts.append("High-pressure urgency tactics detected")
        elif urgency_score > 0.4:
            parts.append("Moderate urgency indicators present")

        # Authority impersonation
        if authority_claims:
            claims_str = ", ".join(authority_claims)
            parts.append(f"Impersonates: {claims_str}")

        # Payment demands
        if payment_escalation:
            parts.append("Contains payment/financial demands")

        # Channel switching
        if channel_switch_intent:
            parts.append(f"Attempts to redirect to {channel_switch_intent}")

        if not parts:
            return "Direct payment request without advanced social-engineering patterns"

        return ". ".join(parts) + "."


# Module-level instance
_ssf_engine: Optional[SSFEngine] = None


def get_ssf_engine() -> SSFEngine:
    """Get SSFEngine instance"""
    global _ssf_engine
    if _ssf_engine is None:
        _ssf_engine = SSFEngine()
    return _ssf_engine
