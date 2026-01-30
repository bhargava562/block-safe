"""
BlockSafe Text Analysis Module
Text-based intelligence extraction and analysis
"""

import re
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class TextSignals:
    """Text-based signals for analysis"""
    word_count: int
    sentence_count: int
    avg_sentence_length: float
    exclamation_count: int
    question_count: int
    caps_ratio: float
    suspicious_keywords: List[str]


class TextAnalyzer:
    """
    Analyzes text for linguistic patterns and signals.
    Complements LLM-based classification with rule-based signals.
    """

    # Suspicious keywords commonly found in scams
    SUSPICIOUS_KEYWORDS = [
        # Urgency
        "urgent", "immediately", "act now", "don't delay", "limited time",
        "expire", "deadline", "last chance", "final notice",
        # Authority
        "bank", "police", "government", "official", "authorized",
        "rbi", "income tax", "customs",
        # Money/Payment
        "pay", "transfer", "upi", "account", "fee", "charge",
        "fine", "penalty", "refund", "prize", "lottery", "winner",
        # Action
        "click", "verify", "confirm", "update", "download",
        "call", "contact", "reply",
        # Threat
        "blocked", "suspended", "closed", "legal", "arrest",
        "court", "lawsuit", "action"
    ]

    def analyze(self, text: str) -> TextSignals:
        """
        Analyze text for various signals.

        Args:
            text: Input text to analyze

        Returns:
            TextSignals dataclass with analysis results
        """
        # Basic counts
        words = text.split()
        word_count = len(words)

        # Sentence analysis
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]
        sentence_count = len(sentences)

        avg_sentence_length = (
            sum(len(s.split()) for s in sentences) / sentence_count
            if sentence_count > 0 else 0
        )

        # Punctuation analysis
        exclamation_count = text.count('!')
        question_count = text.count('?')

        # Caps analysis
        alpha_chars = [c for c in text if c.isalpha()]
        caps_ratio = (
            sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
            if alpha_chars else 0
        )

        # Keyword detection
        text_lower = text.lower()
        suspicious_keywords = [
            kw for kw in self.SUSPICIOUS_KEYWORDS
            if kw in text_lower
        ]

        return TextSignals(
            word_count=word_count,
            sentence_count=sentence_count,
            avg_sentence_length=round(avg_sentence_length, 2),
            exclamation_count=exclamation_count,
            question_count=question_count,
            caps_ratio=round(caps_ratio, 3),
            suspicious_keywords=list(set(suspicious_keywords))
        )

    def calculate_scam_likelihood(self, signals: TextSignals) -> float:
        """
        Calculate basic scam likelihood from text signals.
        This is a supplementary score, not the primary classification.

        Args:
            signals: TextSignals from analysis

        Returns:
            Score from 0-1 indicating scam likelihood
        """
        score = 0.0

        # Suspicious keywords (major factor)
        keyword_score = min(len(signals.suspicious_keywords) / 5, 1.0) * 0.4
        score += keyword_score

        # Exclamation marks (urgency indicator)
        if signals.exclamation_count > 2:
            score += 0.1

        # High caps ratio (shouting)
        if signals.caps_ratio > 0.3:
            score += 0.1

        # Very short sentences (commands)
        if signals.avg_sentence_length < 5 and signals.sentence_count > 2:
            score += 0.1

        return min(score, 1.0)


# Module-level instance
_text_analyzer: Optional[TextAnalyzer] = None


def get_text_analyzer() -> TextAnalyzer:
    """Get TextAnalyzer instance"""
    global _text_analyzer
    if _text_analyzer is None:
        _text_analyzer = TextAnalyzer()
    return _text_analyzer
