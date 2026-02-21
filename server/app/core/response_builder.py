"""
BlockSafe Response Builder
Deterministic JSON response assembly
"""

from datetime import datetime, timezone
from typing import Optional, Literal
from uuid import uuid4

from app.api.v1.schemas import (
    AnalysisResponse,
    ExtractedEntities,
    SSFProfile,
    VoiceAnalysisResult,
    HoneypotResponseDetails,
    HoneypotResult as HoneypotResponseModel,
    AIFeedback,
    CampaignInfo
)
from app.core.scam_detector import ClassificationResult
from app.core.ssf_engine import SSFResult
from app.core.honeypot import HoneypotResult, TerminationReason
from app.intelligence.voice_analysis import VoiceSignals
from app.utils.helpers import ExtractedData, count_entities


class ResponseBuilder:
    """
    Builds deterministic JSON responses for API output.
    Ensures consistent structure for judge evaluation.
    """

    @staticmethod
    def build(
        classification: ClassificationResult,
        ssf: SSFResult,
        honeypot_result: Optional[HoneypotResult],
        original_message: str,
        mode: Literal["shield", "honeypot"],
        transcript: Optional[str] = None,
        voice_signals: Optional[VoiceSignals] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        multi_agent_result=None,
    ) -> AnalysisResponse:
        """
        Build complete analysis response.

        Args:
            classification: Scam classification result
            ssf: Scam Strategy Fingerprint result
            honeypot_result: Honeypot engagement result (if any)
            original_message: The analyzed message
            mode: Operation mode used
            transcript: Audio transcript (if audio input)
            voice_signals: Voice analysis results (if audio input)
            request_id: Optional pre-generated request ID

        Returns:
            Complete AnalysisResponse
        """
        # Generate request ID and timestamp
        req_id = request_id or str(uuid4())
        sess_id = session_id or str(uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        # Build extracted entities
        entities = ResponseBuilder._build_entities(
            classification.extracted_entities,
            honeypot_result
        )

        # Build SSF profile (enriched with agent cognitive scores if available)
        agent_analysis_data = getattr(classification, 'agent_analysis', None)
        ssf_profile = ResponseBuilder._build_ssf_profile(ssf, agent_analysis=agent_analysis_data)

        # Build voice analysis (if applicable)
        voice_analysis = None
        if voice_signals:
            voice_analysis = VoiceAnalysisResult(
                speech_rate=voice_signals.speech_rate,
                urgency_indicators=voice_signals.urgency_indicators,
                repetition_detected=voice_signals.repetition_detected
            )

        # Build honeypot result (if applicable)
        honeypot_response = None
        if honeypot_result and honeypot_result.engaged and honeypot_result.conversation_history:
             last_turn = honeypot_result.conversation_history[-1]
             
             # Extract attributes we attached dynamically
             trust_score = getattr(last_turn, "trust_score", 0.0)
             alternate_content = getattr(last_turn, "alternate_content", None)
             scammer_tone = getattr(last_turn, "scammer_tone", None)
             agent_tone = getattr(last_turn, "agent_tone", None)
             
             honeypot_response = HoneypotResponseDetails(
                 content=last_turn.agent_response,
                 trust_score=trust_score,
                 alternate_content=alternate_content,
                 scammer_tone=scammer_tone,
                 agent_tone=agent_tone,
                 is_active=honeypot_result.engaged,
                 total_extracted_entities=ResponseBuilder._entities_to_model(honeypot_result.all_entities)
             )
        
        # Legacy HoneypotResult mapping (if needed, but AnalysisResponse uses honeypot_result field directly with the core model)
        # The schema uses HoneypotResult from schemas.py which matches app.core.honeypot.HoneypotResult structure partially?
        # api/v1/schemas.py defines HoneypotResult.
        # core/honeypot.py defines HoneypotResult.
        # They seem to be different classes with same name?
        # schemas.py: 
        # class HoneypotResult(BaseModel): ...
        # core/honeypot.py:
        # @dataclass class HoneypotResult: ...
        
        # ResponseBuilder imports HoneypotResult from core.honeypot.
        # But schemas.py has HoneypotResult model.
        # And AnalysisResponse expects honeypot_result: Optional[HoneypotResult] (from schemas).
        
        # We need to convert core dataclass to schema model.
        
        honeypot_result_model = None
        if honeypot_result:
            honeypot_result_model = HoneypotResponseModel(
                turns_completed=honeypot_result.turns_completed,
                termination_reason=honeypot_result.termination_reason.value,
                additional_entities=ResponseBuilder._entities_to_model(
                    honeypot_result.all_entities
                ),
                conversation_summary=honeypot_result.conversation_summary
            )

        # Calculate evidence level
        evidence_level = ResponseBuilder._calculate_evidence_level(
            classification, ssf, honeypot_result
        )

        # Generate agent summary
        agent_summary = ResponseBuilder._generate_summary(
            classification, ssf, honeypot_result, mode
        )

        # Build multi-agent intelligence fields
        ai_feedback_model = None
        campaign_info_model = None
        effective_confidence = classification.confidence
        provider_used = None

        # Extract provider info from the agent_analysis on classification
        if hasattr(classification, 'agent_analysis') and classification.agent_analysis is not None:
            agent_analysis = classification.agent_analysis
            if hasattr(agent_analysis, 'provider_used'):
                provider_used = agent_analysis.provider_used

        if multi_agent_result:
            ai_feedback_model = AIFeedback(
                openai_emotional_profile=multi_agent_result.psychological_analysis,
                gemini_policy_violations=multi_agent_result.policy_analysis,
                primary_suspected_reason=multi_agent_result.suspected_reason,
            )
            effective_confidence = multi_agent_result.aggregated_scam_score

            campaign_data = multi_agent_result.campaign_result
            if campaign_data and campaign_data.get("campaign_id"):
                campaign_info_model = CampaignInfo(
                    campaign_id=campaign_data["campaign_id"],
                    is_new_campaign=campaign_data.get("is_new_campaign", True),
                    total_attempts_tracked=campaign_data.get("total_attempts_tracked", 1),
                    primary_target_entity=campaign_data.get("primary_target_entity", "Unknown"),
                )

        return AnalysisResponse(
            request_id=req_id,
            session_id=sess_id,
            timestamp=timestamp,
            is_scam=classification.is_scam,
            confidence=round(effective_confidence, 2),
            scam_type=classification.scam_type,
            transcript=transcript,
            original_message=original_message,
            extracted_entities=entities,
            ssf_profile=ssf_profile,
            voice_analysis=voice_analysis,
            honeypot_result=honeypot_result_model,
            honeypot_response=honeypot_response,
            agent_summary=agent_summary,
            evidence_level=evidence_level,
            operation_mode=mode,
            provider_used=provider_used,
            ai_feedback=ai_feedback_model,
            campaign_info=campaign_info_model,
        )

    @staticmethod
    def _build_entities(
        base: ExtractedData,
        honeypot_result: Optional[HoneypotResult]
    ) -> ExtractedEntities:
        """Combine entities from classification and honeypot"""
        if honeypot_result and honeypot_result.engaged:
            # Merge with honeypot-extracted entities
            all_data = honeypot_result.all_entities
        else:
            all_data = base

        return ResponseBuilder._entities_to_model(all_data)

    @staticmethod
    def _entities_to_model(data: ExtractedData) -> ExtractedEntities:
        """Convert ExtractedData to Pydantic model"""
        return ExtractedEntities(
            upi_ids=data.upi_ids,
            bank_accounts=data.bank_accounts,
            urls=data.urls,
            phone_numbers=data.phone_numbers
        )

    @staticmethod
    def _build_ssf_profile(ssf: SSFResult, agent_analysis=None) -> SSFProfile:
        """Convert SSFResult to Pydantic model, enriched with multi-agent cognitive scores"""
        from app.api.v1.schemas import PolicyViolation

        profile = SSFProfile(
            urgency_score=ssf.urgency_score,
            authority_claims=ssf.authority_claims,
            payment_escalation=ssf.payment_escalation,
            channel_switch_intent=ssf.channel_switch_intent,
            urgency_phrases=ssf.urgency_phrases,
            strategy_summary=ssf.strategy_summary,
        )

        # Enrich with multi-agent cognitive scores
        if agent_analysis is not None:
            profile.fear_score = getattr(agent_analysis, 'fear_score', 0.0)
            profile.authority_score = getattr(agent_analysis, 'authority_score', 0.0)
            profile.cognitive_risk_score = getattr(agent_analysis, 'cognitive_risk_score', 0.0)

            # Merge urgency: take the higher of regex-based vs AI-derived
            ai_urgency = getattr(agent_analysis, 'urgency_score', 0.0)
            if ai_urgency > profile.urgency_score:
                profile.urgency_score = round(ai_urgency, 2)

            # Policy violation from Fact-Checker
            if getattr(agent_analysis, 'policy_violation', False):
                entity = getattr(agent_analysis, 'entity', None)
                claimed = getattr(agent_analysis, 'claimed_action', None)
                verified = getattr(agent_analysis, 'verified_result', None)
                if entity and claimed and verified:
                    profile.policy_violation = PolicyViolation(
                        entity=entity,
                        claimed_action=claimed,
                        verified_result=verified,
                        source_url=getattr(agent_analysis, 'source_url', None),
                    )

            # Enhance strategy summary with cognitive data
            if profile.cognitive_risk_score >= 0.7:
                cognitive_note = f"High cognitive risk ({profile.cognitive_risk_score:.1f})"
                if profile.policy_violation:
                    cognitive_note += " with known policy violation"
                if profile.strategy_summary and "No significant" not in profile.strategy_summary:
                    profile.strategy_summary = f"{profile.strategy_summary} {cognitive_note}."
                else:
                    profile.strategy_summary = f"{cognitive_note}."

        return profile

    @staticmethod
    def _calculate_evidence_level(
        classification: ClassificationResult,
        ssf: SSFResult,
        honeypot_result: Optional[HoneypotResult]
    ) -> Literal["NONE", "LOW", "MEDIUM", "HIGH"]:
        """
        Calculate overall evidence level based on multiple signals.
        """
        # Calculate entity count
        entity_count = count_entities(classification.extracted_entities)
        if honeypot_result and honeypot_result.engaged:
            entity_count = count_entities(honeypot_result.all_entities)
        
        # Non-scam cases
        if not classification.is_scam:
            if entity_count > 0:
                return "LOW"  # Financial entities detected = low risk
            else:
                return "NONE"  # No entities = no risk
        
        # Scam cases - calculate score
        score = 0
        
        # Confidence contribution
        if classification.confidence >= 0.9:
            score += 3
        elif classification.confidence >= 0.7:
            score += 2
        elif classification.confidence >= 0.5:
            score += 1
        
        # Entity contribution
        if entity_count >= 3:
            score += 2
        elif entity_count >= 1:
            score += 1
        
        # SSF contribution
        if ssf.urgency_score >= 0.7:
            score += 1
        if ssf.authority_claims:
            score += 1
        if ssf.payment_escalation:
            score += 1
        
        # Honeypot contribution
        if honeypot_result and honeypot_result.engaged:
            score += 1
        
        # Map to evidence level
        if classification.confidence >= 0.8:
            return "HIGH"
        elif score >= 3:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def _generate_summary(
        classification: ClassificationResult,
        ssf: SSFResult,
        honeypot_result: Optional[HoneypotResult],
        mode: str
    ) -> str:
        """Generate human-readable analysis summary"""
        if not classification.is_scam:
            return "No scam indicators detected. Message appears legitimate with low risk signals."

        parts = []

        # Classification summary
        confidence_level = "High" if classification.confidence >= 0.8 else \
                          "Moderate" if classification.confidence >= 0.5 else "Low"

        if classification.scam_type:
            parts.append(
                f"{confidence_level}-confidence {classification.scam_type.replace('_', ' ')} detected."
            )
        else:
            parts.append(f"{confidence_level}-confidence scam detected.")

        # SSF summary
        if ssf.strategy_summary and "No significant" not in ssf.strategy_summary:
            parts.append(ssf.strategy_summary)

        # Honeypot summary
        if honeypot_result:
            if honeypot_result.engaged:
                entity_count = count_entities(honeypot_result.all_entities)
                parts.append(
                    f"Honeypot extracted {entity_count} entities in "
                    f"{honeypot_result.turns_completed} turn(s)."
                )
            elif mode == "shield":
                parts.append("Shield mode active: user protected without engagement.")

        return " ".join(parts)
