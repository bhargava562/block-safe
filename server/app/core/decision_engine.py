"""
BlockSafe Decision Engine
Central decision-making logic for analysis flow
"""

from typing import Optional, Tuple
from dataclasses import dataclass

from app.config import get_settings
from app.core.scam_detector import ClassificationResult
from app.core.ssf_engine import SSFResult


@dataclass
class Decision:
    """Decision output from the engine"""
    should_engage_honeypot: bool
    confidence_level: str  # LOW, MEDIUM, HIGH
    risk_assessment: str
    recommended_action: str


class DecisionEngine:
    """
    Central decision-making engine for BlockSafe.
    Determines actions based on classification and SSF results.
    """

    def evaluate(
        self,
        classification: ClassificationResult,
        ssf: SSFResult,
        mode: str
    ) -> Decision:
        """
        Evaluate classification and SSF to make decisions.

        Args:
            classification: Scam classification result
            ssf: Scam Strategy Fingerprint result
            mode: Operation mode (shield/honeypot)

        Returns:
            Decision with recommended actions
        """
        settings = get_settings()

        # Determine confidence level
        confidence_level = self._get_confidence_level(classification.confidence)

        # Determine if honeypot should engage
        should_engage = (
            mode == "honeypot" and
            classification.is_scam and
            classification.confidence >= settings.HONEYPOT_CONFIDENCE_THRESHOLD
        )

        # Risk assessment
        risk_assessment = self._assess_risk(classification, ssf)

        # Recommended action
        recommended_action = self._get_recommendation(
            classification, ssf, mode, should_engage
        )

        return Decision(
            should_engage_honeypot=should_engage,
            confidence_level=confidence_level,
            risk_assessment=risk_assessment,
            recommended_action=recommended_action
        )

    def _get_confidence_level(self, confidence: float) -> str:
        """Map confidence score to level"""
        if confidence >= 0.85:
            return "HIGH"
        elif confidence >= 0.6:
            return "MEDIUM"
        else:
            return "LOW"

    def _assess_risk(
        self,
        classification: ClassificationResult,
        ssf: SSFResult
    ) -> str:
        """Generate risk assessment summary"""
        if not classification.is_scam:
            return "No significant risk detected."

        risk_factors = []

        if classification.confidence >= 0.9:
            risk_factors.append("Very high confidence scam detection")
        elif classification.confidence >= 0.7:
            risk_factors.append("High confidence scam detection")

        if ssf.urgency_score >= 0.7:
            risk_factors.append("High-pressure tactics detected")

        if ssf.authority_claims:
            risk_factors.append(f"Impersonating: {', '.join(ssf.authority_claims)}")

        if ssf.payment_escalation:
            risk_factors.append("Payment demands present")

        if classification.scam_type:
            risk_factors.append(f"Scam type: {classification.scam_type}")

        if not risk_factors:
            return "Low-level suspicious activity detected."

        return " | ".join(risk_factors)

    def _get_recommendation(
        self,
        classification: ClassificationResult,
        ssf: SSFResult,
        mode: str,
        should_engage: bool
    ) -> str:
        """Generate recommended action"""
        if not classification.is_scam:
            return "No action required. Message appears legitimate."

        if mode == "shield":
            return "Block/ignore message. Do not respond or click any links."

        if should_engage:
            return "Honeypot engagement initiated for intelligence extraction."

        return "Message flagged as suspicious. Recommend user verification through official channels."


# Module-level instance
_decision_engine: Optional[DecisionEngine] = None


def get_decision_engine() -> DecisionEngine:
    """Get DecisionEngine instance"""
    global _decision_engine
    if _decision_engine is None:
        _decision_engine = DecisionEngine()
    return _decision_engine
