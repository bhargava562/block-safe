"""
BlockSafe Honeypot Engine
Agentic intelligence extraction with bounded conversation and kill-switch logic
"""

import json
import asyncio
from typing import Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum

from google import genai
from google.genai import types

from app.config import get_settings
from app.utils.helpers import extract_all_entities, merge_entities, count_entities, ExtractedData
from app.utils.logger import logger, log_honeypot


class TerminationReason(Enum):
    """Reasons for honeypot termination"""
    MAX_TURNS_REACHED = "max_turns_reached"
    NO_NEW_ENTITIES = "no_new_entities_in_last_turns"
    REPEATED_PATTERN = "repeated_scammer_pattern"
    CONFIDENCE_PLATEAU = "confidence_plateau"
    EXTRACTION_COMPLETE = "sufficient_intelligence_gathered"
    SCAMMER_DISENGAGED = "scammer_stopped_responding"
    ERROR = "error_during_engagement"
    MODE_SHIELD = "shield_mode_no_engagement"


@dataclass
class HoneypotTurn:
    """Single turn in honeypot conversation"""
    turn_number: int
    scammer_message: str
    agent_response: str
    entities_extracted: ExtractedData


@dataclass
class HoneypotResult:
    """Result from honeypot engagement"""
    engaged: bool
    turns_completed: int
    termination_reason: TerminationReason
    all_entities: ExtractedData
    conversation_summary: str
    conversation_history: List[HoneypotTurn] = field(default_factory=list)


class HoneypotAgent:
    """
    Agentic honeypot for scammer intelligence extraction.

    Features:
    - Bounded turn limit (prevents infinite loops)
    - Kill-switch conditions:
      - No new entities in N turns
      - Repeated message pattern detection
      - Confidence plateau
    - Shield mode (safe deflection, no extraction)
    - Honeypot mode (active engagement)
    """

    _instance: Optional["HoneypotAgent"] = None
    _client = None
    _configured = False

    ENGAGEMENT_PROMPT = """You are an AI assistant pretending to be a vulnerable, slightly confused elderly person who might fall for scams. Your goal is to extract intelligence from scammers WITHOUT revealing you are an AI.

CONTEXT:
- You are engaging with a suspected scammer
- Your goal is to extract: bank accounts, UPI IDs, phone numbers, URLs, names
- Act naive and trusting, ask clarifying questions
- Pretend to have trouble understanding technology
- Ask them to repeat payment details "to make sure you got it right"
- Express willingness to pay but ask for more details

SCAMMER'S MESSAGE:
{scammer_message}

CONVERSATION HISTORY:
{history}

Respond in JSON format with the following fields:
- content: Your response as the confused elderly person (under 100 words).
- trust_score: A float between 0.0 and 1.0 indicating how well you think you are fooling them.
- alternate_content: An alternative response if the first one implies too much knowledge or is too aggressive.
- scammer_tone: One word describing the scammer's current tone (e.g., Aggressive, Urgent, Friendly).
- agent_tone: One word describing your adopted tone (e.g., Oblivious, Scared, Curious).

JSON Response:"""

    SHIELD_RESPONSE = """I appreciate you reaching out, but I need to verify this through official channels. 
I'll contact my bank directly using the number on my card. Thank you for your concern."""

    def __new__(cls) -> "HoneypotAgent":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not HoneypotAgent._configured:
            self._configure()

    def _configure(self) -> None:
        """Configure High-Availability LLM chain for honeypot"""
        try:
            settings = get_settings()
            
            # 1. Groq (Primary)
            from langchain_groq import ChatGroq
            self.groq_llm = ChatGroq(
                model=settings.GROQ_MODEL,
                api_key=settings.GROQ_API_KEY.get_secret_value() if settings.has_groq else "dummy",
                temperature=0.7,
                max_tokens=512,
                request_timeout=settings.AGENT_TIMEOUT_SECONDS,
                max_retries=1
            )
            
            # 2. DeepSeek (Fallback)
            from langchain_openai import ChatOpenAI
            self.deepseek_llm = ChatOpenAI(
                model=settings.DEEPSEEK_MODEL,
                api_key=settings.DEEPSEEK_API_KEY.get_secret_value() if settings.has_deepseek else "dummy",
                base_url="https://api.deepseek.com/v1",
                temperature=0.7,
                max_tokens=512,
                request_timeout=settings.AGENT_TIMEOUT_SECONDS,
                max_retries=1
            )

            # Define fallback sequence
            fallbacks = []
            if settings.has_deepseek: 
                fallbacks.append(self.deepseek_llm)
            
            self._chain = self.groq_llm.with_fallbacks(fallbacks)
            HoneypotAgent._configured = True
            logger.info("Honeypot agent configured with Groq->DeepSeek fallback chain")

        except Exception as e:
            logger.error(f"Failed to configure honeypot: {e}")
            HoneypotAgent._configured = False

    async def engage(
        self,
        initial_message: str,
        mode: str,
        initial_entities: ExtractedData,
        request_id: str,
        history: List[dict] = None,
        turns_completed: int = 0
    ) -> HoneypotResult:
        """
        Engage with scammer or return shield response.
        Args:
            initial_message: The scam message
            mode: "shield" or "honeypot"
            initial_entities: Already extracted entities
            request_id: For logging
            history: Optional list of past messages [{role, text}]
            turns_completed: Number of turns already performed in this session
        """
        settings = get_settings()

        # Check configuration
        if not self._configured:
             self._configure()
             if not self._configured:
                logger.error("Honeypot agent not configured, defaulting to shield mode")
                return HoneypotResult(
                    engaged=False,
                    turns_completed=0,
                    termination_reason=TerminationReason.ERROR,
                    all_entities=initial_entities,
                    conversation_summary="Honeypot unavailable (configuration error).",
                    conversation_history=[]
                )

        # Shield mode - no engagement
        if mode == "shield":
            return HoneypotResult(
                engaged=False,
                turns_completed=0,
                termination_reason=TerminationReason.MODE_SHIELD,
                all_entities=initial_entities,
                conversation_summary="Shield mode: Safe deflection response provided, no active engagement.",
                conversation_history=[]
            )

        # ── Governor's Kill Switch ──
        if turns_completed >= settings.HONEYPOT_MAX_TURNS:
            log_honeypot(request_id, turns_completed, "kill_switch_triggered")
            return HoneypotResult(
                engaged=False,
                turns_completed=turns_completed,
                termination_reason=TerminationReason.MAX_TURNS_REACHED,
                all_entities=initial_entities,
                conversation_summary="Governor's Kill Switch: Max turns reached. Session terminated.",
                conversation_history=[]
            )

        # ── Perform Reactive Turn ──
        try:
            # 1. Format context
            history_str = self._format_history_from_db(history)
            
            # 2. Generate AI response
            response_data = await self._generate_response(initial_message, history_str)
            
            response_content = response_data.get("content", "")
            trust_score = response_data.get("trust_score", 0.0)
            alternate_content = response_data.get("alternate_content", "")
            scammer_tone = response_data.get("scammer_tone", "Unknown")
            agent_tone = response_data.get("agent_tone", "Neutral")

            # 3. Extract entities
            turn_entities = extract_all_entities(initial_message + " " + response_content)
            all_entities = merge_entities(initial_entities, turn_entities)

            # 4. Build turn object
            turn_obj = HoneypotTurn(
                turn_number=turns_completed + 1,
                scammer_message=initial_message,
                agent_response=response_content,
                entities_extracted=turn_entities
            )
            turn_obj.trust_score = trust_score
            turn_obj.alternate_content = alternate_content
            turn_obj.scammer_tone = scammer_tone
            turn_obj.agent_tone = agent_tone

            # Determine termination reason
            reason = TerminationReason.EXTRACTION_COMPLETE if count_entities(all_entities) >= 5 else TerminationReason.MAX_TURNS_REACHED if (turns_completed + 1) >= settings.HONEYPOT_MAX_TURNS else TerminationReason.SCAMMER_DISENGAGED
            
            if reason == TerminationReason.SCAMMER_DISENGAGED:
                # This is a temporary state until next message
                summary = f"Honeypot turn {turns_completed + 1} successful. Context maintained."
            else:
                summary = self._generate_summary([turn_obj], all_entities, reason)

            return HoneypotResult(
                engaged=True,
                turns_completed=turns_completed + 1,
                termination_reason=reason,
                all_entities=all_entities,
                conversation_summary=summary,
                conversation_history=[turn_obj]
            )

        except Exception as e:
            logger.error(f"Honeypot engagement error: {e}")
            return HoneypotResult(
                engaged=False,
                turns_completed=turns_completed,
                termination_reason=TerminationReason.ERROR,
                all_entities=initial_entities,
                conversation_summary=f"Internal agent error: {str(e)}",
                conversation_history=[]
            )

    def _format_history_from_db(self, history: List[dict] = None) -> str:
        """Format history retrieved from Supabase for the LLM prompt"""
        if not history:
            return "No previous conversation"

        lines = []
        for msg in history:
            role = "Scammer" if msg["sender_role"] == "scammer" else "You"
            lines.append(f"{role}: {msg['message_text']}")

        return "\n".join(lines)

    async def _generate_response(self, scammer_message: str, history: str) -> dict:
        """Generate honeypot response using High-Availability chain"""
        
        if not self._configured:
            self._configure()
            if not self._configured:
                raise RuntimeError("Honeypot model not initialized")

        prompt = self.ENGAGEMENT_PROMPT.format(
            scammer_message=scammer_message,
            history=history or "No previous conversation"
        )

        try:
            # Use ainvoke for LLM call
            from langchain_core.messages import HumanMessage
            response = await self._chain.ainvoke([HumanMessage(content=prompt)])
            text = response.content.strip()
            
            # Remove markdown fences if any
            if "```" in text:
                 text = text.replace("```json", "").replace("```", "")
            
            # Find JSON object boundaries
            start = text.find("{")
            end = text.rfind("}")
            
            if start != -1 and end != -1:
                text = text[start:end+1]
            
            return json.loads(text)
        except Exception as e:
            logger.error(f"Honeypot AI error: {e}")
            return self._get_fallback_response()

        try:
            text = response.text.strip()
            # Remove markdown fences
            if "```" in text:
                 text = text.replace("```json", "").replace("```", "")
            
            # Find JSON object boundaries
            start = text.find("{")
            end = text.rfind("}")
            
            if start != -1 and end != -1:
                text = text[start:end+1]
            
            return json.loads(text)
        except json.JSONDecodeError:
            # Fallback if JSON is malformed
            return {
                "content": response.text.strip(),
                "trust_score": 0.5,
                "alternate_content": None,
                "scammer_tone": "Unknown",
                "agent_tone": "Neutral"
            }

    def _get_fallback_response(self) -> dict:
        """Provide safe fallback response when AI fails"""
        import random
        safe_responses = [
            "I'm not sure I understand. Can you explain that again?",
            "My grandson usually handles this. What do I need to do?",
            "Is there a website I can visit to check this?",
            "I'm a bit confused. Who is this again?",
            "Can you tell me more about how this works?",
            "I want to help, but I'm not good with these things. What is the first step?"
        ]
        return {
            "content": random.choice(safe_responses),
            "trust_score": 0.3,
            "alternate_content": "Please verify your identity.",
            "scammer_tone": "Unknown",
            "agent_tone": "Confused"
        }

    def _format_history(self, history: List[HoneypotTurn]) -> str:
        """Format conversation history for prompt"""
        if not history:
            return ""

        lines = []
        for turn in history[-3:]:  # Only last 3 turns for context
            lines.append(f"Scammer: {turn.scammer_message}")
            lines.append(f"You: {turn.agent_response}")

        return "\n".join(lines)

    def _is_repeated_pattern(self, current: str, previous: List[str]) -> bool:
        """Detect if scammer is repeating the same message"""
        if not previous:
            return False

        current_normalized = current.lower().strip()
        for prev in previous:
            prev_normalized = prev.lower().strip()
            # Check for high similarity (simple approach)
            if current_normalized == prev_normalized:
                return True
            # Check if 80% similar words
            current_words = set(current_normalized.split())
            prev_words = set(prev_normalized.split())
            if current_words and prev_words:
                overlap = len(current_words & prev_words) / max(len(current_words), len(prev_words))
                if overlap > 0.8:
                    return True

        return False

    def _build_result(
        self,
        history: List[HoneypotTurn],
        entities: ExtractedData,
        reason: TerminationReason
    ) -> HoneypotResult:
        """Build final HoneypotResult"""
        summary = self._generate_summary(history, entities, reason)

        return HoneypotResult(
            engaged=len(history) > 0,
            turns_completed=len(history),
            termination_reason=reason,
            all_entities=entities,
            conversation_summary=summary,
            conversation_history=history
        )

    def _generate_summary(
        self,
        history: List[HoneypotTurn],
        entities: ExtractedData,
        reason: TerminationReason
    ) -> str:
        """Generate human-readable summary"""
        if not history:
            return f"No engagement performed. Reason: {reason.value}"

        entity_count = count_entities(entities)

        parts = [
            f"Honeypot engaged for {len(history)} turn(s).",
            f"Extracted {entity_count} total entities.",
            f"Termination: {reason.value}."
        ]

        if entities.upi_ids:
            parts.append(f"UPI IDs found: {', '.join(entities.upi_ids)}")
        if entities.bank_accounts:
            parts.append(f"Bank accounts found: {', '.join(entities.bank_accounts)}")
        if entities.urls:
            parts.append(f"URLs found: {', '.join(entities.urls)}")

        return " ".join(parts)

    def get_shield_response(self) -> str:
        """Get safe shield mode response"""
        return self.SHIELD_RESPONSE


def get_honeypot_agent() -> HoneypotAgent:
    """Get singleton HoneypotAgent instance"""
    return HoneypotAgent()
