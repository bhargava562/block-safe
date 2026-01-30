"""
BlockSafe Behavior Signals Module
Behavioral pattern detection and analysis
"""

from typing import List, Optional
from dataclasses import dataclass

from app.intelligence.text_analysis import TextSignals
from app.intelligence.voice_analysis import VoiceSignals


@dataclass
class BehaviorProfile:
    """Combined behavioral profile from multiple signal sources"""
    manipulation_score: float  # 0-1, how manipulative the communication is
    pressure_tactics: List[str]  # Detected pressure tactics
    social_engineering_indicators: List[str]  # SE technique indicators
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL


class BehaviorAnalyzer:
    """
    Analyzes behavioral patterns across text and voice signals.
    Detects social engineering tactics and manipulation attempts.
    """

    # Pressure tactics patterns
    PRESSURE_TACTICS = {
        "time_pressure": ["immediately", "right now", "urgent", "expire", "deadline"],
        "authority_pressure": ["police", "government", "bank", "official", "rbi"],
        "fear_appeal": ["blocked", "suspended", "arrest", "legal action", "court"],
        "scarcity": ["limited", "only", "last chance", "final"],
        "social_proof": ["everyone", "others have", "many people"],
    }

    # Social engineering indicators
    SE_INDICATORS = {
        "pretexting": ["we noticed", "our records show", "according to"],
        "baiting": ["free", "prize", "winner", "reward", "cashback"],
        "quid_pro_quo": ["in exchange", "if you", "once you"],
        "impersonation": ["this is", "i am from", "calling from"],
    }

    def analyze(
        self,
        text: str,
        text_signals: Optional[TextSignals] = None,
        voice_signals: Optional[VoiceSignals] = None
    ) -> BehaviorProfile:
        """
        Generate behavioral profile from available signals.

        Args:
            text: Original message text
            text_signals: Text analysis results
            voice_signals: Voice analysis results

        Returns:
            BehaviorProfile with manipulation assessment
        """
        text_lower = text.lower()

        # Detect pressure tactics
        detected_tactics = []
        for tactic, keywords in self.PRESSURE_TACTICS.items():
            if any(kw in text_lower for kw in keywords):
                detected_tactics.append(tactic)

        # Detect SE indicators
        se_indicators = []
        for indicator, phrases in self.SE_INDICATORS.items():
            if any(phrase in text_lower for phrase in phrases):
                se_indicators.append(indicator)

        # Calculate manipulation score
        manipulation_score = self._calculate_manipulation_score(
            detected_tactics,
            se_indicators,
            text_signals,
            voice_signals
        )

        # Determine risk level
        risk_level = self._determine_risk_level(manipulation_score, len(detected_tactics))

        return BehaviorProfile(
            manipulation_score=round(manipulation_score, 2),
            pressure_tactics=detected_tactics,
            social_engineering_indicators=se_indicators,
            risk_level=risk_level
        )

    def _calculate_manipulation_score(
        self,
        tactics: List[str],
        se_indicators: List[str],
        text_signals: Optional[TextSignals],
        voice_signals: Optional[VoiceSignals]
    ) -> float:
        """Calculate overall manipulation score"""
        score = 0.0

        # Tactics contribution (0.4 max)
        score += min(len(tactics) / 3, 1.0) * 0.4

        # SE indicators contribution (0.3 max)
        score += min(len(se_indicators) / 2, 1.0) * 0.3

        # Text signals contribution
        if text_signals:
            if text_signals.exclamation_count > 3:
                score += 0.1
            if text_signals.caps_ratio > 0.3:
                score += 0.1

        # Voice signals contribution
        if voice_signals:
            if voice_signals.speech_rate > 180:
                score += 0.1
            if voice_signals.repetition_detected:
                score += 0.05

        return min(score, 1.0)

    def _determine_risk_level(self, score: float, tactic_count: int) -> str:
        """Determine risk level from score and tactics"""
        if score >= 0.8 or tactic_count >= 4:
            return "CRITICAL"
        elif score >= 0.6 or tactic_count >= 3:
            return "HIGH"
        elif score >= 0.3 or tactic_count >= 2:
            return "MEDIUM"
        else:
            return "LOW"


# Module-level instance
_behavior_analyzer: Optional[BehaviorAnalyzer] = None


def get_behavior_analyzer() -> BehaviorAnalyzer:
    """Get BehaviorAnalyzer instance"""
    global _behavior_analyzer
    if _behavior_analyzer is None:
        _behavior_analyzer = BehaviorAnalyzer()
    return _behavior_analyzer
