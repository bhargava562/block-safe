"""
BlockSafe API Schemas
Pydantic models for request/response validation
"""

from datetime import datetime
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field


# === Request Models ===

class TextInput(BaseModel):
    """Input model for text-based scam analysis"""

    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="The text message to analyze for scam detection"
    )
    mode: Literal["shield", "honeypot"] = Field(
        default="shield",
        description="Operation mode: 'shield' for protection only, 'honeypot' for active intelligence extraction"
    )
    session_id: Optional[str] = Field(
        default=None,
        description="Session ID for continuous chat (auto-generated if not provided)"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "message": "Your bank account has been blocked. Click here to verify: http://fake-bank.com",
                    "mode": "shield"
                }
            ]
        }
    }


class AudioInput(BaseModel):
    """Metadata model for audio analysis (file comes via multipart)"""

    mode: Literal["shield", "honeypot"] = Field(
        default="shield",
        description="Operation mode: 'shield' for protection only, 'honeypot' for active intelligence extraction"
    )


# === Response Models ===

class ExtractedEntities(BaseModel):
    """Entities extracted from scam content"""

    upi_ids: list[str] = Field(default_factory=list, description="Extracted UPI IDs (e.g., name@upi)")
    bank_accounts: list[str] = Field(default_factory=list, description="Extracted bank account numbers")
    urls: list[str] = Field(default_factory=list, description="Extracted URLs")
    phone_numbers: list[str] = Field(default_factory=list, description="Extracted phone numbers")


class PolicyViolation(BaseModel):
    """Result of real-time policy fact-checking against official sources"""

    entity: str = Field(..., description="Organization mentioned (e.g., 'SBI Bank')")
    claimed_action: str = Field(..., description="What the message claims the entity requires")
    verified_result: str = Field(..., description="Fact-check finding from official sources")
    source_url: Optional[str] = Field(default=None, description="URL of the official source")


class SSFProfile(BaseModel):
    """Scam Strategy Fingerprint - behavioral pattern analysis"""

    urgency_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Urgency level detected (0-1)"
    )
    authority_claims: list[str] = Field(
        default_factory=list,
        description="Authority figures claimed (e.g., 'RBI', 'Police', 'Bank Manager')"
    )
    payment_escalation: bool = Field(
        default=False,
        description="Whether payment demands escalate during interaction"
    )
    channel_switch_intent: Optional[str] = Field(
        default=None,
        description="Detected intent to switch channels (e.g., 'WhatsApp', 'Telegram')"
    )
    urgency_phrases: list[str] = Field(
        default_factory=list,
        description="Specific urgency phrases detected"
    )
    strategy_summary: str = Field(
        default="",
        description="Human-readable summary of scam strategy"
    )

    # ── Multi-Agent Cognitive Scores (from Profiler Agent) ──
    fear_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Fear induction level from cognitive risk profiler (0-1)"
    )
    authority_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Authority impersonation level from cognitive risk profiler (0-1)"
    )
    cognitive_risk_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Aggregated cognitive manipulation risk score (0-1)"
    )

    # ── Policy Fact-Check (from Fact-Checker Agent) ──
    policy_violation: Optional[PolicyViolation] = Field(
        default=None,
        description="Real-time policy verification result (null if no institutional claims)"
    )


class VoiceAnalysisResult(BaseModel):
    """Voice-specific analysis results (for audio inputs)"""

    speech_rate: float = Field(
        default=0.0,
        description="Words per minute detected"
    )
    urgency_indicators: list[str] = Field(
        default_factory=list,
        description="Voice-based urgency indicators"
    )
    repetition_detected: bool = Field(
        default=False,
        description="Whether repetitive patterns were detected"
    )


class HoneypotResult(BaseModel):
    """Results from honeypot engagement (only in honeypot mode)"""

    turns_completed: int = Field(default=0, description="Number of conversation turns")
    termination_reason: str = Field(default="", description="Why honeypot engagement ended")
    additional_entities: ExtractedEntities = Field(
        default_factory=ExtractedEntities,
        description="Additional entities extracted during engagement"
    )
    conversation_summary: str = Field(default="", description="Summary of honeypot conversation")


class AIFeedback(BaseModel):
    """Multi-agent AI analysis feedback from the LangGraph swarm"""

    openai_emotional_profile: str = Field(
        default="",
        description="OpenAI CognitiveProfiler: psychological manipulation analysis"
    )
    gemini_policy_violations: str = Field(
        default="",
        description="Gemini PolicyValidator: real-world policy violation analysis"
    )
    primary_suspected_reason: str = Field(
        default="",
        description="Synthesized reason combining both agents' findings"
    )


class CampaignInfo(BaseModel):
    """Campaign clustering result from the Merging Intervals engine"""

    campaign_id: str = Field(..., description="Campaign identifier (e.g., CAMP-SBI-KYC-001)")
    is_new_campaign: bool = Field(..., description="True if a new campaign was created, False if merged")
    total_attempts_tracked: int = Field(default=1, description="Total scam attempts tracked in this campaign")
    primary_target_entity: str = Field(default="Unknown", description="Entity being impersonated")


class AnalysisResponse(BaseModel):
    """Complete analysis response - deterministic JSON output"""

    request_id: str = Field(..., description="Unique request identifier (UUID)")
    session_id: str = Field(..., description="Session identifier for continuous chat")
    timestamp: str = Field(..., description="ISO-8601 timestamp of analysis")

    # Classification results
    is_scam: bool = Field(..., description="Whether the content is classified as a scam")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Classification confidence (0-1)"
    )
    scam_type: Optional[str] = Field(
        default=None,
        description="Type of scam detected (e.g., 'bank_impersonation', 'upi_fraud', 'phishing')"
    )

    # Content
    transcript: Optional[str] = Field(
        default=None,
        description="Transcribed text (for audio inputs)"
    )
    original_message: str = Field(..., description="The analyzed message content")

    # Extracted intelligence
    extracted_entities: ExtractedEntities = Field(
        default_factory=ExtractedEntities,
        description="Entities extracted from content"
    )

    # Scam Strategy Fingerprint
    ssf_profile: SSFProfile = Field(
        ...,
        description="Scam Strategy Fingerprint analysis"
    )

    # Voice analysis (audio only)
    voice_analysis: Optional[VoiceAnalysisResult] = Field(
        default=None,
        description="Voice analysis results (audio inputs only)"
    )

    # Honeypot results
    honeypot_result: Optional[HoneypotResult] = Field(
        default=None,
        description="Honeypot engagement results (honeypot mode only)"
    )

    # Honeypot engagement details
    honeypot_response: Optional["HoneypotResponseDetails"] = Field(
        default=None,
        description="Detailed honeypot agent response and status"
    )

    # Summary
    agent_summary: str = Field(..., description="AI-generated summary of the analysis")
    evidence_level: Literal["NONE", "LOW", "MEDIUM", "HIGH"] = Field(
        ...,
        description="Overall evidence level for scam classification"
    )
    operation_mode: Literal["shield", "honeypot"] = Field(
        ...,
        description="Mode used for this analysis"
    )
    provider_used: Optional[str] = Field(
        default=None,
        description="AI provider(s) that handled this request (e.g., 'openai_gemini_primary', 'groq_fallback_triggered')"
    )

    # Multi-Agent Intelligence (from LangGraph swarm)
    ai_feedback: Optional[AIFeedback] = Field(
        default=None,
        description="Multi-agent AI feedback: emotional profiling + policy validation"
    )
    campaign_info: Optional[CampaignInfo] = Field(
        default=None,
        description="Campaign clustering result from Merging Intervals engine"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "request_id": "550e8400-e29b-41d4-a716-446655440000",
                    "timestamp": "2026-01-30T12:00:00Z",
                    "is_scam": True,
                    "confidence": 0.95,
                    "scam_type": "bank_impersonation",
                    "transcript": None,
                    "original_message": "Your account is blocked, click here...",
                    "extracted_entities": {
                        "upi_ids": ["scammer@upi"],
                        "bank_accounts": [],
                        "urls": ["http://fake-bank.com"],
                        "phone_numbers": []
                    },
                    "ssf_profile": {
                        "urgency_score": 0.9,
                        "authority_claims": ["Bank"],
                        "payment_escalation": False,
                        "channel_switch_intent": None,
                        "urgency_phrases": ["immediately", "blocked"],
                        "strategy_summary": "Classic bank impersonation with urgency tactics"
                    },
                    "voice_analysis": None,
                    "honeypot_result": None,
                    "honeypot_response": {
                        "content": "Oh my, I am so worried. How do I fix this?",
                        "trust_score": 0.95,
                        "alternate_content": "I don't understand, can you explain again?",
                        "is_active": True,
                        "total_extracted_entities": {
                            "upi_ids": [],
                            "bank_accounts": [],
                            "urls": ["http://fake-bank.com"],
                            "phone_numbers": []
                        }
                    },
                    "agent_summary": "High-confidence bank impersonation scam detected.",
                    "evidence_level": "HIGH",
                    "operation_mode": "shield"
                }
            ]
        }
    }


class HoneypotResponseDetails(BaseModel):
    """Detailed honeypot agent response and status"""
    content: str = Field(..., description="The honeypot agent's reply text")
    trust_score: float = Field(default=0.0, description="Trust score of the agent (simulated)")
    alternate_content: Optional[str] = Field(default=None, description="Alternate reply text if switch needed")
    
    # Tone Analysis
    scammer_tone: Optional[str] = Field(default=None, description="Detected tone of the scammer (e.g., Aggressive, Urgent)")
    agent_tone: Optional[str] = Field(default=None, description="Adopted tone of the honeypot agent (e.g., Oblivious, Scared)")
    
    is_active: bool = Field(default=True, description="Is honeypot currently active")
    total_extracted_entities: ExtractedEntities = Field(..., description="Accumulated extracted entities for this session")


class HealthResponse(BaseModel):
    """Health check response"""

    status: str = Field(default="healthy")
    version: str = Field(default="1.0.0")
    timestamp: str = Field(..., description="Current server time")
