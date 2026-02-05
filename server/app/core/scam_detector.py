"""
BlockSafe Scam Detector Module
Gemini-powered scam classification using google-genai
"""

import json
import time
from typing import Optional
from dataclasses import dataclass
from copy import deepcopy

from google import genai
from google.genai import types

from app.config import get_settings
from app.utils.logger import logger
from app.utils.helpers import extract_all_entities, ExtractedData, count_entities
from app.core.dataset_manager import get_dataset_manager


@dataclass
class ClassificationResult:
    """Result from scam classification"""
    is_scam: bool
    confidence: float
    scam_type: Optional[str]
    reasoning: str
    extracted_entities: ExtractedData


class ScamClassifier:
    """
    Gemini-powered scam detection classifier.
    Returns structured classification with confidence scores.
    """

    _instance: Optional["ScamClassifier"] = None
    _client = None
    _configured = False
    _cache: dict[str, tuple[float, ClassificationResult]] = {}
    _cache_ttl: int = 300  # seconds
    _cache_max: int = 100

    CLASSIFICATION_PROMPT = """You are an expert scam detection system. Analyze the following message and determine if it is a scam.

MESSAGE TO ANALYZE:
{message}

Analyze for these scam indicators:
1. Urgency or pressure tactics ("immediately", "urgent", "act now")
2. Requests for personal/financial information:
   - Credit/debit card numbers (16 digits, CVV, expiry)
   - Bank account details, PIN, passwords
   - OTP, verification codes
   - Personal documents (Aadhaar, PAN)
3. Suspicious links or contact methods
4. Impersonation of authority figures (bank, police, government)
5. Too-good-to-be-true offers
6. Payment demands or threats of account blocking
7. Requests to switch communication channels

CRITICAL: Any request for card numbers, CVV, PIN, OTP, or banking credentials is HIGH RISK scam.

Respond ONLY with valid JSON in this exact format:
{{
    "is_scam": true/false,
    "confidence": 0.0-1.0,
    "scam_type": "card_fraud" | "bank_impersonation" | "upi_fraud" | "phishing" | "lottery_scam" | "tech_support_scam" | "investment_scam" | "romance_scam" | "job_scam" | "government_impersonation" | null,
    "reasoning": "Brief explanation of classification"
}}

For card/banking credential requests: is_scam=true, confidence=0.9+, scam_type="card_fraud"""

    def __new__(cls) -> "ScamClassifier":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not ScamClassifier._configured:
            self._configure()
        self.dataset_manager = get_dataset_manager()

    def _configure(self) -> None:
        """Configure Gemini API client"""
        try:
            settings = get_settings()

            # Initialize the new google-genai client
            ScamClassifier._client = genai.Client(
                api_key=settings.GEMINI_API_KEY.get_secret_value()
            )

            ScamClassifier._configured = True
            logger.info(f"Scam classifier configured with model: {settings.GEMINI_MODEL}")

        except Exception as e:
            logger.error(f"Failed to configure Gemini: {e}")
            raise RuntimeError(f"Gemini configuration failed: {e}")

    async def classify(self, message: str) -> ClassificationResult:
        """
        Classify a message for scam detection.

        Args:
            message: The text message to analyze

        Returns:
            ClassificationResult with is_scam, confidence, scam_type, reasoning
        """
        if self._client is None:
            raise RuntimeError("Scam classifier not initialized")

        # Extract entities using regex first
        entities = extract_all_entities(message)
        settings = get_settings()

        # Serve from cache when available and fresh
        cached = self._get_cached(message)
        if cached:
            logger.debug("Classification cache hit")
            return deepcopy(cached)

        try:
            # Generate classification using the new API
            prompt = self.CLASSIFICATION_PROMPT.format(message=message)

            response = await self._client.aio.models.generate_content(
                model=settings.GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.0,  # Deterministic output
                    top_p=0.95,
                    top_k=40,
                    max_output_tokens=512,  # Reduced for faster response
                )
            )

            # Parse JSON response
            result = self._parse_response(response.text)
            result.extracted_entities = entities
            
            # Adjust confidence based on detected entities (risk calibration)
            result = self._calibrate_confidence(result, entities)
            
            # Cache successful result
            self._set_cache(message, result)

            return result

        except Exception as e:
            logger.error(f"Classification failed: {e}")
            # Return safe default with risk-based confidence
            entity_count = len(entities.phone_numbers) + len(entities.upi_ids) + len(entities.urls)
            base_confidence = min(entity_count * 0.1, 0.3)  # 0.1-0.3 for detected entities
            
            return ClassificationResult(
                is_scam=False,
                confidence=base_confidence,
                scam_type=None,
                reasoning=f"Classification error: {str(e)}",
                extracted_entities=entities
            )

    def _parse_response(self, response_text: str) -> ClassificationResult:
        """Parse Gemini response into ClassificationResult"""
        try:
            # Clean response - extract JSON from potential markdown
            text = response_text.strip()
            if text.startswith("```"):
                # Remove markdown code blocks
                lines = text.split("\n")
                json_lines = [l for l in lines if not l.startswith("```")]
                text = "\n".join(json_lines)

            data = json.loads(text)

            return ClassificationResult(
                is_scam=bool(data.get("is_scam", False)),
                confidence=float(data.get("confidence", 0.0)),
                scam_type=data.get("scam_type"),
                reasoning=str(data.get("reasoning", "")),
                extracted_entities=ExtractedData([], [], [], [])  # Will be set by caller
            )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse classification response: {e}")
            logger.debug(f"Raw response: {response_text}")

            # Attempt basic extraction with risk-based confidence
            is_scam = "true" in response_text.lower() and "is_scam" in response_text.lower()
            
            # Calculate confidence based on detected entities
            entity_count = 0  # Will be updated by caller
            base_confidence = 0.15 if is_scam else 0.05  # Non-zero baseline

            return ClassificationResult(
                is_scam=is_scam,
                confidence=base_confidence,
                scam_type=None,
                reasoning="Response parsing failed, using fallback classification",
                extracted_entities=ExtractedData([], [], [], [])
            )

    def _calibrate_confidence(self, result: ClassificationResult, entities: ExtractedData) -> ClassificationResult:
        """Calibrate confidence based on detected financial entities"""
        entity_count = count_entities(entities)
        
        if not result.is_scam and result.confidence == 0.0 and entity_count > 0:
            # Non-scam with financial entities = low but non-zero risk
            result.confidence = min(0.1 + (entity_count * 0.05), 0.3)
        
        return result

    def _get_cached(self, message: str) -> Optional[ClassificationResult]:
        now = time.time()
        entry = self._cache.get(message)
        if not entry:
            return None
        ts, result = entry
        if now - ts > self._cache_ttl:
            # Expired
            self._cache.pop(message, None)
            return None
        return result

    def _set_cache(self, message: str, result: ClassificationResult) -> None:
        # Evict oldest if over max size
        if len(self._cache) >= self._cache_max:
            oldest_key = next(iter(self._cache.keys()))
            self._cache.pop(oldest_key, None)
        self._cache[message] = (time.time(), deepcopy(result))

    @classmethod
    def is_configured(cls) -> bool:
        """Check if classifier is configured"""
        return cls._configured


def get_classifier() -> ScamClassifier:
    """Get the singleton ScamClassifier instance"""
    return ScamClassifier()
