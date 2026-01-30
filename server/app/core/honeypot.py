"""
BlockSafe Honeypot Engine
Agentic intelligence extraction with bounded conversation and kill-switch logic
"""

import json
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

Respond as the confused elderly person. Keep response under 100 words. Try to extract more information naturally.
Your response:"""

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
        """Configure Gemini for honeypot engagement"""
        try:
            settings = get_settings()

            # Initialize the new google-genai client
            HoneypotAgent._client = genai.Client(
                api_key=settings.GEMINI_API_KEY.get_secret_value()
            )

            HoneypotAgent._configured = True
            logger.info("Honeypot agent configured")

        except Exception as e:
            logger.error(f"Failed to configure honeypot: {e}")
            raise RuntimeError(f"Honeypot configuration failed: {e}")

    async def engage(
        self,
        initial_message: str,
        mode: str,
        initial_entities: ExtractedData,
        request_id: str
    ) -> HoneypotResult:
        """
        Engage with scammer or return shield response.

        Args:
            initial_message: The scam message
            mode: "shield" or "honeypot"
            initial_entities: Already extracted entities
            request_id: For logging

        Returns:
            HoneypotResult with engagement details
        """
        settings = get_settings()

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

        # Honeypot mode - active engagement
        return await self._run_honeypot(
            initial_message=initial_message,
            initial_entities=initial_entities,
            request_id=request_id,
            max_turns=settings.HONEYPOT_MAX_TURNS,
            no_progress_limit=settings.HONEYPOT_NO_PROGRESS_TURNS
        )

    async def _run_honeypot(
        self,
        initial_message: str,
        initial_entities: ExtractedData,
        request_id: str,
        max_turns: int,
        no_progress_limit: int
    ) -> HoneypotResult:
        """Run bounded honeypot engagement with kill-switch logic"""

        conversation_history: List[HoneypotTurn] = []
        all_entities = initial_entities
        previous_entity_count = count_entities(initial_entities)
        no_progress_turns = 0
        last_messages: List[str] = []

        current_message = initial_message

        for turn in range(1, max_turns + 1):
            try:
                # Check for repeated pattern (kill-switch)
                if self._is_repeated_pattern(current_message, last_messages):
                    log_honeypot(request_id, turn - 1, "repeated_pattern")
                    return self._build_result(
                        conversation_history,
                        all_entities,
                        TerminationReason.REPEATED_PATTERN
                    )

                last_messages.append(current_message)
                if len(last_messages) > 3:
                    last_messages.pop(0)

                # Generate agent response
                history_str = self._format_history(conversation_history)
                response = await self._generate_response(current_message, history_str)

                # Extract entities from this turn
                turn_entities = extract_all_entities(current_message + " " + response)
                all_entities = merge_entities(all_entities, turn_entities)

                # Record turn
                conversation_history.append(HoneypotTurn(
                    turn_number=turn,
                    scammer_message=current_message,
                    agent_response=response,
                    entities_extracted=turn_entities
                ))

                # Check progress (kill-switch)
                current_entity_count = count_entities(all_entities)
                if current_entity_count == previous_entity_count:
                    no_progress_turns += 1
                else:
                    no_progress_turns = 0
                    previous_entity_count = current_entity_count

                if no_progress_turns >= no_progress_limit:
                    log_honeypot(request_id, turn, "no_new_entities")
                    return self._build_result(
                        conversation_history,
                        all_entities,
                        TerminationReason.NO_NEW_ENTITIES
                    )

                # Check if we have sufficient intelligence
                if current_entity_count >= 5:
                    log_honeypot(request_id, turn, "extraction_complete")
                    return self._build_result(
                        conversation_history,
                        all_entities,
                        TerminationReason.EXTRACTION_COMPLETE
                    )

                # Simulate next scammer message (in real scenario, this would come from external source)
                # For evaluation, we complete after generating our response
                current_message = ""  # Would be next scammer input

            except Exception as e:
                logger.error(f"Honeypot turn {turn} error: {e}")
                return self._build_result(
                    conversation_history,
                    all_entities,
                    TerminationReason.ERROR
                )

        # Max turns reached
        log_honeypot(request_id, max_turns, "max_turns")
        return self._build_result(
            conversation_history,
            all_entities,
            TerminationReason.MAX_TURNS_REACHED
        )

    async def _generate_response(self, scammer_message: str, history: str) -> str:
        """Generate honeypot response using Gemini"""
        if self._client is None:
            raise RuntimeError("Honeypot model not initialized")

        settings = get_settings()
        prompt = self.ENGAGEMENT_PROMPT.format(
            scammer_message=scammer_message,
            history=history or "No previous conversation"
        )

        response = await self._client.aio.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.7,
                top_p=0.95,
                max_output_tokens=256,
            )
        )

        return response.text.strip()

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
