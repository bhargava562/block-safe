"""
BlockSafe Scam Detector Module
Multi-agent scam classification with LangChain orchestration and Groq fallback.
"""

import json
import time
import asyncio
from typing import Optional
from dataclasses import dataclass, field as dc_field
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
    extracted_entities: "ExtractedData" = None
    agent_analysis: object = dc_field(default=None, repr=False)  # AgentAnalysis from multi-agent pipeline


class ScamClassifier:
    """
    Multi-agent scam detection classifier.
    Uses LangChain-powered Profiler + Fact-Checker agents with automatic Groq fallback.
    Falls back to rule-based classification when all AI providers are unavailable.
    """

    _instance: Optional["ScamClassifier"] = None
    _client = None
    _configured = False
    _cache: dict[str, tuple[float, ClassificationResult]] = {}
    _cache_ttl: int = 300    # overridden from config at init
    _cache_max: int = 256    # overridden from config at init

    CLASSIFICATION_PROMPT = """You are an expert scam detection system. Analyze the following message and determine if it is a scam.
    
KNOWN SCAM PATTERNS (Reference Database):
{context}

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

8. Advance fee / Processing fee requests for loans or prizes (Key indicator)

CRITICAL: Any request for card numbers, CVV, PIN, OTP, banking credentials, or upfront payment for a loan/prize is HIGH RISK scam.

Respond ONLY with valid JSON in this exact format:
{{
    "is_scam": true/false,
    "confidence": 0.0-1.0,
    "scam_type": "card_fraud" | "bank_impersonation" | "upi_fraud" | "phishing" | "lottery_scam" | "tech_support_scam" | "investment_scam" | "romance_scam" | "job_scam" | "government_impersonation" | "loan_scam" | null,
    "reasoning": "Brief explanation of classification"
}}

For card/banking credential requests: is_scam=true, confidence=0.9+, scam_type="card_fraud"
For advance fee loans: is_scam=true, confidence=0.9+, scam_type="loan_scam" """

    def __new__(cls) -> "ScamClassifier":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not ScamClassifier._configured:
            self._configure()
        # Wire cache limits from config (bounded, no memory leak)
        settings = get_settings()
        ScamClassifier._cache_max = settings.CLASSIFICATION_CACHE_MAX
        ScamClassifier._cache_ttl = settings.CLASSIFICATION_CACHE_TTL
        self.dataset_manager = get_dataset_manager()

    def _configure(self) -> None:
        """Configure Gemini API client"""
        try:
            settings = get_settings()

            # Initialize the new google-genai client
            if settings.GEMINI_API_KEY:
                ScamClassifier._client = genai.Client(
                    api_key=settings.GEMINI_API_KEY.get_secret_value()
                )
                ScamClassifier._configured = True
                logger.info(f"Scam classifier configured with model: {settings.GEMINI_MODEL}")
            else:
                logger.warning("GEMINI_API_KEY is missing. Classifier will use rule-based fallback.")
                ScamClassifier._configured = False

        except Exception as e:
            logger.error(f"Failed to configure Gemini: {e}")
            ScamClassifier._configured = False
            # Do not raise here, allow app to start

    async def classify(self, message: str) -> ClassificationResult:
        """
        Classify a message for scam detection using multi-agent pipeline.

        Flow: entity extraction → rule pre-check → cache → run_agents() → result

        Args:
            message: The text message to analyze

        Returns:
            ClassificationResult with is_scam, confidence, scam_type, reasoning
        """
        # Extract entities first
        extracted_entities = extract_all_entities(message)
        entity_count = count_entities(extracted_entities)

        # Check cache
        cached = self._get_cached(message)
        if cached:
            logger.debug("Classification cache hit")
            return deepcopy(cached)

        # RULE-BASED PRE-CHECK: High-risk patterns (instant, no API call)
        if self._has_critical_indicators(message, extracted_entities):
            logger.warning("Critical scam indicators detected via rules")
            result = ClassificationResult(
                is_scam=True,
                confidence=0.95,
                scam_type="card_fraud" if any(kw in message.lower() for kw in ['cvv', 'pin', 'otp', 'card number']) else "phishing",
                reasoning="Critical indicators: Requests sensitive credentials or urgent payment",
                extracted_entities=extracted_entities
            )
            self._set_cache(message, result)
            return result

        # ── MULTI-AGENT PIPELINE ──────────────────────────────
        try:
            from app.intelligence.agents import run_agents
            agent_result = await run_agents(message)

            # Map AgentAnalysis → ClassificationResult
            reasoning_parts = []
            if agent_result.profiler_reasoning:
                reasoning_parts.append(f"Profiler: {agent_result.profiler_reasoning}")
            if agent_result.fact_checker_reasoning:
                reasoning_parts.append(f"Fact-Check: {agent_result.fact_checker_reasoning}")
            if agent_result.policy_violation and agent_result.verified_result:
                reasoning_parts.append(f"Policy Violation: {agent_result.verified_result}")

            result = ClassificationResult(
                is_scam=agent_result.is_scam,
                confidence=agent_result.confidence,
                scam_type=agent_result.scam_type,
                reasoning=" | ".join(reasoning_parts) if reasoning_parts else "Multi-agent analysis complete",
                extracted_entities=extracted_entities,
                agent_analysis=agent_result,
            )

            # Calibrate confidence with entity evidence
            result = self._calibrate_confidence(result, extracted_entities)

            # Cache successful result
            self._set_cache(message, result)

            # Trigger async learning for high-confidence scams
            if result.is_scam and result.confidence > 0.8:
                asyncio.create_task(self._learn_pattern(message, result))

            return result

        except Exception as e:
            logger.error(f"Multi-agent classification failed: {e}")

        # ── LEGACY GEMINI FALLBACK ────────────────────────────
        # If multi-agent pipeline fails, fall back to direct Gemini API
        if not self._configured or self._client is None:
            self._configure()

        if not self._configured or self._client is None:
            logger.error("All AI providers unavailable, using rule-based fallback")
            return self._rule_based_fallback(message, extracted_entities)

        try:
            relevant_patterns = self.dataset_manager.find_similar_patterns(message, threshold=0.05)
            context_str = "No specific consistent patterns found in database."
            if relevant_patterns:
                context_str = "\n".join([
                    f"- Type: {p.scam_type}\n  Keywords: {', '.join(p.common_keywords)}\n  Description: {p.description}"
                    for p in relevant_patterns[:3]
                ])

            prompt = self._build_prompt(message, context_str, extracted_entities)

            response = None
            retry_delay = 5
            for attempt in range(5):
                try:
                    response = await self._client.aio.models.generate_content(
                        model=get_settings().GEMINI_MODEL,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            temperature=0.0,
                            top_p=0.95,
                            top_k=40,
                            max_output_tokens=512,
                            response_mime_type="application/json"
                        )
                    )
                    break
                except Exception as e:
                    if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                        if attempt < 4:
                            wait_time = retry_delay * (2 ** attempt)
                            logger.warning(f"Rate limited (429), retrying in {wait_time}s...")
                            await asyncio.sleep(wait_time)
                            continue
                    raise e

            if response is None:
                raise RuntimeError("Failed to get response after retries")

            result = self._parse_response(response.text)
            result.extracted_entities = extracted_entities
            result = self._calibrate_confidence(result, extracted_entities)
            self._set_cache(message, result)

            if result.is_scam and result.confidence > 0.8:
                asyncio.create_task(self._learn_pattern(message, result))

            return result

        except Exception as e:
            logger.error(f"Legacy Gemini fallback also failed: {e}")
            return self._rule_based_fallback(message, extracted_entities)

    def _has_critical_indicators(self, message: str, entities: ExtractedData) -> bool:
        """Check for critical scam indicators using rules"""
        msg_lower = message.lower()
        
        # Critical keywords
        critical_keywords = [
            'cvv', 'pin', 'otp', 'verification code', 'card number',
            'debit card', 'credit card', 'net banking password',
            'aadhaar', 'pan card', 'bank account', 'processing fee',
            'advance fee', 'upfront payment'
        ]
        
        # Urgency phrases
        urgency_phrases = [
            'immediately', 'urgent', 'within 24 hours', 'expire',
            'suspended', 'blocked', 'verify now', 'act now', 'today only'
        ]
        
        # Check combinations
        has_critical_keyword = any(kw in msg_lower for kw in critical_keywords)
        has_urgency = any(phrase in msg_lower for phrase in urgency_phrases)
        has_financial_entities = len(entities.phone_numbers) > 0 or len(entities.upi_ids) > 0 or len(entities.urls) > 0
        
        # Critical if asks for credentials OR (urgency + contact info + loan/prize context)
        is_loan_prize = any(kw in msg_lower for kw in ['loan', 'prize', 'winner', 'lottery'])
        
        return has_critical_keyword or (has_urgency and has_financial_entities) or (is_loan_prize and (has_financial_entities or 'fee' in msg_lower))

    def _rule_based_fallback(self, message: str, entities: ExtractedData) -> ClassificationResult:
        """Fallback classification using rules when AI fails"""
        
        if self._has_critical_indicators(message, entities):
            return ClassificationResult(
                is_scam=True,
                confidence=0.85,
                scam_type="phishing",
                reasoning="Rule-based detection: Critical scam indicators present (Fallback)",
                extracted_entities=entities
            )
        
        entity_count = count_entities(entities)
        return ClassificationResult(
            is_scam=False,
            confidence=min(entity_count * 0.05, 0.2),
            scam_type=None,
            reasoning="No classification available, low entity risk (Fallback)",
            extracted_entities=entities
        )

    def _build_prompt(self, message: str, context: str, entities: ExtractedData) -> str:
        """Build enhanced prompt with entity information"""
        
        entity_summary = f"""
    DETECTED ENTITIES:
    - Phone numbers: {len(entities.phone_numbers)}
    - UPI IDs: {len(entities.upi_ids)}
    - URLs: {len(entities.urls)}
    - Card numbers: {len(entities.card_numbers) if hasattr(entities, 'card_numbers') else 0}
    """
        
        return f"""{self.CLASSIFICATION_PROMPT.format(message=message, context=context)}

    {entity_summary}

    IMPORTANT: Weight these factors heavily:
    - Multiple entities (phone + URL + UPI) = Higher risk
    - Requests for CVV, PIN, OTP, passwords = CRITICAL (confidence 0.95+)
    - Urgency + payment/credentials = High risk
    - Too-good-to-be-true offers + payment = Medium-High risk
    - Loan offers requiring "advance fee" or "processing fee" = High risk (confidence 0.9+)
    """

    async def _learn_pattern(self, message: str, result: ClassificationResult) -> None:
        """Analyze high-confidence scam to learn new patterns"""
        try:
            # Check if similar pattern exists
            similar = self.dataset_manager.find_similar_patterns(message, threshold=0.8)
            if similar:
                logger.debug("Pattern already known, skipping learning")
                return

            # Generate pattern extraction prompt
            prompt = f"""Analyze this NEW scam message and extract its structural pattern for the database.
            
            MESSAGE:
            {message}
            
            SCAM TYPE: {result.scam_type}
            
            Respond ONLY with valid JSON matching this schema:
            {{
                "category": "Broad Category (e.g., Banking, Job, Crypto, etc.)",
                "scam_type": "Specific Type",
                "channels": ["call", "sms", "whatsapp", "etc"],
                "description": "General description of how this scam works",
                "common_keywords": ["list", "of", "keywords", "found"],
                "behavioral_patterns": ["creates urgency", "asks for OTP", "etc"],
                "risk_level": "high" or "critical" or "medium"
            }}
            """
            
            # Call Gemini
            if not self._client:
                logger.debug("AI client not configured, skipping pattern learning")
                return

            settings = get_settings()
            response = await self._client.aio.models.generate_content(
                model=settings.GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.0,
                    response_mime_type="application/json"
                )
            )
            
            # Parse response
            text = response.text.strip()
            # Clean response - manual extraction
            if "```" in text:
                 text = text.replace("```json", "").replace("```", "")
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1:
                text = text[start:end+1]
                
            new_pattern = json.loads(text)
            
            # Add to dataset
            self.dataset_manager.add_new_pattern(new_pattern)
            
        except Exception as e:
            logger.error(f"Failed to learn new pattern: {e}")

    def _parse_response(self, response_text: str) -> ClassificationResult:
        """Parse Gemini response into ClassificationResult"""
        try:
            # Clean response - manual extraction
            text = response_text.strip()
            
            # Remove markdown fences if present
            if "```" in text:
                 text = text.replace("```json", "").replace("```", "")
            
            # Find JSON object boundaries
            start = text.find("{")
            end = text.rfind("}")
            
            if start != -1 and end != -1:
                text = text[start:end+1]

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
