"""
BlockSafe Multi-Agent Swarm
LangGraph StateGraph orchestrator with 5 sub-agents across 3 execution layers.

Layer 1 (Parallel):  CognitiveProfiler, PolicyValidator, ArtifactExtractor
Layer 2 (Sequential): CampaignCluster
Layer 3 (Conditional): HoneypotGovernor (delegated to existing honeypot.py)

Architecture: "Split-Brain / Multi-Agent" routing
"""

import asyncio
import json
import re
from typing import Optional, Dict, Any, List, TypedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from langgraph.graph import StateGraph, END

from app.config import get_settings
from app.core.scam_detector import ClassificationResult
from app.core.ssf_engine import SSFResult
from app.utils.helpers import (
    extract_all_entities, ExtractedData,
    extract_urls, extract_phone_numbers, extract_upi_ids
)
from app.utils.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
# Shared State Schema (TypedDict for LangGraph)
# ─────────────────────────────────────────────────────────────────────────────

class ScamState(TypedDict, total=False):
    """Shared state flowing through the LangGraph StateGraph."""
    # Input
    message: str
    classification: Dict[str, Any]
    ssf_result: Dict[str, Any]

    # Layer 1 outputs
    cognitive_profile: Dict[str, Any]
    policy_validation: Dict[str, Any]
    extracted_artifacts: Dict[str, Any]

    # Layer 2 outputs
    campaign_result: Dict[str, Any]

    # Synthesis
    aggregated_scam_score: float
    suspected_reason: str
    ai_feedback: Dict[str, Any]

    # Metadata
    errors: List[str]


# ─────────────────────────────────────────────────────────────────────────────
# Result Dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MultiAgentResult:
    """Final output from the multi-agent swarm."""
    psychological_analysis: str
    policy_analysis: str
    aggregated_scam_score: float
    suspected_reason: str
    urgency_score: float
    fear_score: float
    authority_score: float
    extracted_artifacts: Dict[str, Any]
    campaign_result: Dict[str, Any]
    errors: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Sub-Agent 1: CognitiveProfiler (OpenAI gpt-4o-mini → Groq fallback)
# ─────────────────────────────────────────────────────────────────────────────

async def _run_cognitive_profiler(message: str) -> Dict[str, Any]:
    """
    Measures psychological manipulation: urgency, fear, authority.
    Uses OpenAI gpt-4o-mini with Groq llama-3.3-70b as fallback.
    """
    settings = get_settings()

    system_prompt = (
        "You are a Cognitive Threat Analyst. Ignore the factual claims of the message. "
        "Your ONLY job is to detect the presence of urgency, fear induction, and "
        "authority impersonation. Also provide a short psychological_analysis string "
        "explaining the manipulation tactics detected.\n\n"
        "Output STRICTLY as JSON with these exact keys:\n"
        '{"fear_score": 0.0-1.0, "urgency_score": 0.0-1.0, "authority_score": 0.0-1.0, '
        '"psychological_analysis": "string explaining tactics"}'
    )

    # Try OpenAI first
    if settings.has_openai:
        try:
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(
                model=settings.OPENAI_MODEL,
                api_key=settings.OPENAI_API_KEY.get_secret_value() if settings.has_openai else "dummy",
                temperature=0.1,
                max_tokens=512,
                request_timeout=settings.REQUEST_TIMEOUT_SECONDS,
            )
            response = await llm.ainvoke([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze this message:\n\n{message}"}
            ])
            result = _parse_json_response(response.content)
            if result:
                logger.info("CognitiveProfiler: OpenAI success")
                return result
        except Exception as e:
            logger.warning(f"CognitiveProfiler: OpenAI failed ({e}), falling back to Groq")

    # Fallback to Groq
    if settings.has_groq:
        try:
            from langchain_groq import ChatGroq

            llm = ChatGroq(
                model=settings.GROQ_MODEL,
                api_key=settings.GROQ_API_KEY.get_secret_value() if settings.has_groq else "dummy",
                temperature=0.1,
                max_tokens=512,
                request_timeout=settings.REQUEST_TIMEOUT_SECONDS,
            )
            response = await llm.ainvoke([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze this message:\n\n{message}"}
            ])
            result = _parse_json_response(response.content)
            if result:
                logger.info("CognitiveProfiler: Groq fallback success")
                return result
        except Exception as e:
            logger.warning(f"CognitiveProfiler: Groq fallback failed ({e}), falling back to DeepSeek")

    # Fallback to DeepSeek
    if settings.has_deepseek:
        try:
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(
                model=settings.DEEPSEEK_MODEL,
                api_key=settings.DEEPSEEK_API_KEY.get_secret_value() if settings.has_deepseek else "dummy",
                base_url="https://api.deepseek.com/v1",
                temperature=0.1,
                max_tokens=512,
                request_timeout=settings.REQUEST_TIMEOUT_SECONDS,
            )
            response = await llm.ainvoke([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze this message:\n\n{message}"}
            ])
            result = _parse_json_response(response.content)
            if result:
                logger.info("CognitiveProfiler: DeepSeek fallback success")
                return result
        except Exception as e:
            logger.error(f"CognitiveProfiler: DeepSeek fallback also failed ({e})")

    # Final fallback: rule-based heuristics
    return _heuristic_cognitive_profile(message)


# ─────────────────────────────────────────────────────────────────────────────
# Sub-Agent 2: PolicyValidator (Gemini gemini-1.5-flash → Groq fallback)
# ─────────────────────────────────────────────────────────────────────────────

async def _run_policy_validator(message: str) -> Dict[str, Any]:
    """
    Extracts claimed entity and verifies claims against real-world policies.
    Uses Gemini with Google Search grounding, falls back to Groq.
    """
    settings = get_settings()

    system_prompt = (
        "You are a Corporate Policy Validator. Your job:\n"
        "1. Extract the claimed entity (e.g., 'SBI Bank', 'Amazon', 'Income Tax Dept')\n"
        "2. Extract the required action (e.g., 'Update PAN via link', 'Pay fine via UPI')\n"
        "3. Determine if this entity actually communicates this way\n"
        "4. Check if the required action violates the entity's known policies\n\n"
        "Output STRICTLY as JSON with these exact keys:\n"
        '{"claimed_entity": "string", "required_action": "string", '
        '"policy_violation": true/false, '
        '"policy_analysis": "string explaining the violation or legitimacy"}'
    )

    # Try Gemini with search grounding
    try:
        from google import genai
        from google.genai import types

        if not settings.GEMINI_API_KEY:
             raise ValueError("GEMINI_API_KEY missing")
        
        client = genai.Client(
            api_key=settings.GEMINI_API_KEY.get_secret_value()
        )

        # Use Google Search grounding for real-world policy verification
        try:
            response = await client.aio.models.generate_content(
                model=settings.GEMINI_MODEL,
                contents=f"{system_prompt}\n\nMessage to validate:\n{message}",
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    max_output_tokens=512,
                    tools=[types.Tool(google_search=types.GoogleSearch())],
                )
            )
        except Exception:
            # Fallback without search grounding if not supported
            response = await client.aio.models.generate_content(
                model=settings.GEMINI_MODEL,
                contents=f"{system_prompt}\n\nMessage to validate:\n{message}",
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    max_output_tokens=512,
                )
            )

        result = _parse_json_response(response.text)
        if result:
            logger.info("PolicyValidator: Gemini success")
            return result
    except Exception as e:
        logger.warning(f"PolicyValidator: Gemini failed ({e}), falling back to Groq")

    # Fallback to Groq
    if settings.has_groq:
        try:
            from langchain_groq import ChatGroq

            llm = ChatGroq(
                model=settings.GROQ_MODEL,
                api_key=settings.GROQ_API_KEY.get_secret_value() if settings.has_groq else "dummy",
                temperature=0.1,
                max_tokens=512,
                request_timeout=settings.REQUEST_TIMEOUT_SECONDS,
            )
            response = await llm.ainvoke([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Validate this message:\n\n{message}"}
            ])
            result = _parse_json_response(response.content)
            if result:
                logger.info("PolicyValidator: Groq fallback success")
                return result
        except Exception as e:
            logger.warning(f"PolicyValidator: Groq fallback failed ({e}), falling back to DeepSeek")

    # Fallback to DeepSeek
    if settings.has_deepseek:
        try:
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(
                model=settings.DEEPSEEK_MODEL,
                api_key=settings.DEEPSEEK_API_KEY.get_secret_value() if settings.has_deepseek else "dummy",
                base_url="https://api.deepseek.com/v1",
                temperature=0.1,
                max_tokens=512,
                request_timeout=settings.REQUEST_TIMEOUT_SECONDS,
            )
            response = await llm.ainvoke([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Validate this message:\n\n{message}"}
            ])
            result = _parse_json_response(response.content)
            if result:
                logger.info("PolicyValidator: DeepSeek fallback success")
                return result
        except Exception as e:
            logger.error(f"PolicyValidator: DeepSeek fallback also failed ({e})")

    return {
        "claimed_entity": "Unknown",
        "required_action": "Unknown",
        "policy_violation": False,
        "policy_analysis": "Unable to verify — all AI providers unavailable."
    }


# ─────────────────────────────────────────────────────────────────────────────
# Sub-Agent 3: ArtifactExtractor (Pure Regex — zero latency)
# ─────────────────────────────────────────────────────────────────────────────

def _run_artifact_extractor(message: str) -> Dict[str, Any]:
    """
    Surgically extracts all Indicators of Compromise (IoCs) via regex.
    No LLM needed — pure speed.
    """
    entities = extract_all_entities(message)

    # Also extract raw domains from URLs for matching
    extracted_domains = []
    for url in entities.urls:
        domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/\s]+)', url)
        if domain_match:
            extracted_domains.append(domain_match.group(1).lower())

    # Extract any bare domains that aren't full URLs (e.g., "sbi-secure.in")
    bare_domain_pattern = re.compile(
        r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b'
    )
    for match in bare_domain_pattern.findall(message):
        domain = match.lower()
        # Filter out common non-domain patterns
        if domain not in extracted_domains and not domain.startswith('www.'):
            extracted_domains.append(domain)

    # Detect channel from message content
    channels_detected = _detect_channels(message)

    logger.info(
        f"ArtifactExtractor: {len(entities.urls)} URLs, "
        f"{len(entities.phone_numbers)} phones, "
        f"{len(entities.upi_ids)} UPIs, "
        f"{len(extracted_domains)} domains"
    )

    return {
        "extracted_links": list(set(entities.urls)),
        "extracted_phones": list(set(entities.phone_numbers)),
        "extracted_upis": list(set(entities.upi_ids)),
        "extracted_domains": list(set(extracted_domains)),
        "channels_detected": channels_detected,
    }


def _detect_channels(message: str) -> List[str]:
    """Detect communication channels mentioned in the message."""
    channels = []
    msg_lower = message.lower()

    channel_keywords = {
        "SMS": ["sms", "text message", "message received"],
        "WhatsApp": ["whatsapp", "wa.me"],
        "Email": ["email", "e-mail", "mail"],
        "Call": ["call", "phone call", "dial", "ring"],
        "Telegram": ["telegram", "t.me"],
        "UPI": ["upi", "gpay", "phonepe", "paytm"],
    }

    for channel, keywords in channel_keywords.items():
        if any(kw in msg_lower for kw in keywords):
            channels.append(channel)

    # Default to SMS if no channel detected
    if not channels:
        channels.append("SMS")

    return channels


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2: Decision Synthesis Engine
# ─────────────────────────────────────────────────────────────────────────────

def _synthesize_decision(
    cognitive: Dict[str, Any],
    policy: Dict[str, Any],
    classification: ClassificationResult
) -> tuple:
    """
    Combines Layer 1 outputs into a final aggregated score and reason.
    If Gemini finds a policy violation AND OpenAI detects high emotional
    pressure, the Final Scam Score goes to 0.95+.
    """
    fear = cognitive.get("fear_score", 0.0)
    urgency = cognitive.get("urgency_score", 0.0)
    authority = cognitive.get("authority_score", 0.0)
    policy_violation = policy.get("policy_violation", False)

    # Emotional pressure = average of fear + urgency + authority
    emotional_pressure = (fear + urgency + authority) / 3.0

    # Base score from existing classifier
    base_score = classification.confidence

    # Synthesis logic
    if policy_violation and emotional_pressure >= 0.6:
        # Strong evidence from both agents → 0.95+
        aggregated_score = max(0.95, base_score)
    elif policy_violation:
        # Policy violation alone → boost to at least 0.85
        aggregated_score = max(0.85, base_score)
    elif emotional_pressure >= 0.7:
        # High emotional pressure alone → boost to at least 0.80
        aggregated_score = max(0.80, base_score)
    else:
        aggregated_score = base_score

    # Build suspected reason
    reasons = []
    if policy_violation:
        entity = policy.get("claimed_entity", "Unknown entity")
        reasons.append(
            f"Violates {entity}'s official communication policy"
        )
    if fear >= 0.7:
        reasons.append("High fear induction detected")
    if urgency >= 0.7:
        reasons.append("Artificial urgency pressure applied")
    if authority >= 0.7:
        reasons.append("Authority figure impersonation present")

    if classification.scam_type:
        reasons.append(f"Matches pattern: {classification.scam_type}")

    suspected_reason = ". ".join(reasons) if reasons else "Low risk indicators."

    return aggregated_score, suspected_reason


# ─────────────────────────────────────────────────────────────────────────────
# LangGraph StateGraph Nodes
# ─────────────────────────────────────────────────────────────────────────────

async def layer1_parallel_node(state: ScamState) -> ScamState:
    """
    Layer 1: Run CognitiveProfiler, PolicyValidator, ArtifactExtractor
    in parallel via asyncio.gather().
    """
    message = state["message"]
    errors = list(state.get("errors", []))

    # Run all three agents simultaneously
    cognitive_task = _run_cognitive_profiler(message)
    policy_task = _run_policy_validator(message)

    try:
        cognitive_result, policy_result = await asyncio.gather(
            cognitive_task, policy_task, return_exceptions=True
        )

        # Handle exceptions from gather
        if isinstance(cognitive_result, Exception):
            errors.append(f"CognitiveProfiler error: {cognitive_result}")
            cognitive_result = _heuristic_cognitive_profile(message)

        if isinstance(policy_result, Exception):
            errors.append(f"PolicyValidator error: {policy_result}")
            policy_result = {
                "claimed_entity": "Unknown", "required_action": "Unknown",
                "policy_violation": False,
                "policy_analysis": "Validation unavailable due to error."
            }

    except Exception as e:
        errors.append(f"Layer 1 parallel execution error: {e}")
        cognitive_result = _heuristic_cognitive_profile(message)
        policy_result = {
            "claimed_entity": "Unknown", "required_action": "Unknown",
            "policy_violation": False,
            "policy_analysis": "Validation unavailable due to error."
        }

    # ArtifactExtractor is synchronous (regex, no LLM)
    artifact_result = _run_artifact_extractor(message)

    state["cognitive_profile"] = cognitive_result
    state["policy_validation"] = policy_result
    state["extracted_artifacts"] = artifact_result
    state["errors"] = errors

    return state


async def synthesis_node(state: ScamState) -> ScamState:
    """
    Layer 2: Synthesize Layer 1 outputs into final scores and
    trigger campaign clustering.
    """
    cognitive = state.get("cognitive_profile", {})
    policy = state.get("policy_validation", {})
    classification_data = state.get("classification", {})

    # Reconstruct a minimal ClassificationResult for synthesis
    mock_classification = ClassificationResult(
        is_scam=classification_data.get("is_scam", False),
        confidence=classification_data.get("confidence", 0.0),
        scam_type=classification_data.get("scam_type"),
        reasoning=classification_data.get("reasoning", ""),
        extracted_entities=ExtractedData(
            upi_ids=[], bank_accounts=[], urls=[], phone_numbers=[]
        )
    )

    aggregated_score, suspected_reason = _synthesize_decision(
        cognitive, policy, mock_classification
    )

    # Build AI feedback object
    ai_feedback = {
        "openai_emotional_profile": cognitive.get(
            "psychological_analysis",
            "No emotional profile available."
        ),
        "gemini_policy_violations": policy.get(
            "policy_analysis",
            "No policy analysis available."
        ),
        "primary_suspected_reason": suspected_reason,
    }

    state["aggregated_scam_score"] = round(aggregated_score, 4)
    state["suspected_reason"] = suspected_reason
    state["ai_feedback"] = ai_feedback

    return state


async def campaign_cluster_node(state: ScamState) -> ScamState:
    """
    Layer 2 continued: Run the CampaignCluster logic.
    Uses the CampaignManager to merge or create campaigns.
    """
    from app.core.campaign_manager import get_campaign_manager

    try:
        campaign_mgr = get_campaign_manager()

        campaign_result = await campaign_mgr.process_scam(
            message=state["message"],
            artifacts=state.get("extracted_artifacts", {}),
            ai_feedback=state.get("ai_feedback", {}),
            aggregated_score=state.get("aggregated_scam_score", 0.0),
            claimed_entity=state.get("policy_validation", {}).get(
                "claimed_entity", "Unknown"
            ),
            scam_category=state.get("classification", {}).get(
                "scam_type", "Unknown"
            ),
        )
        state["campaign_result"] = campaign_result

    except Exception as e:
        logger.error(f"CampaignCluster error: {e}")
        errors = list(state.get("errors", []))
        errors.append(f"CampaignCluster error: {e}")
        state["errors"] = errors
        state["campaign_result"] = {
            "campaign_id": "UNKNOWN",
            "is_new_campaign": False,
            "total_attempts_tracked": 0,
            "primary_target_entity": "Unknown",
        }

    return state


# ─────────────────────────────────────────────────────────────────────────────
# LangGraph StateGraph Builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_swarm_graph() -> StateGraph:
    """
    Builds the LangGraph StateGraph:
    layer1_parallel → synthesis → campaign_cluster → END
    """
    graph = StateGraph(ScamState)

    # Add nodes
    graph.add_node("layer1_parallel", layer1_parallel_node)
    graph.add_node("synthesis", synthesis_node)
    graph.add_node("campaign_cluster", campaign_cluster_node)

    # Define edges (sequential flow)
    graph.set_entry_point("layer1_parallel")
    graph.add_edge("layer1_parallel", "synthesis")
    graph.add_edge("synthesis", "campaign_cluster")
    graph.add_edge("campaign_cluster", END)

    return graph


# ─────────────────────────────────────────────────────────────────────────────
# Main Orchestrator Class
# ─────────────────────────────────────────────────────────────────────────────

class AgentSwarm:
    """
    Master Orchestrator: LangGraph StateGraph Router.

    Not an LLM — it is the framework that receives the incoming message,
    creates a shared ScamState, and triggers parallel sub-agents.
    Manages quota fallback (routing to Groq if OpenAI/Gemini fail).
    """

    _instance: Optional["AgentSwarm"] = None
    _graph = None
    _compiled = None

    def __new__(cls) -> "AgentSwarm":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._graph is None:
            self._graph = _build_swarm_graph()
            self._compiled = self._graph.compile()
            logger.info("AgentSwarm: LangGraph StateGraph compiled")

    async def analyze(
        self,
        message: str,
        classification: ClassificationResult,
        ssf_result: SSFResult,
    ) -> MultiAgentResult:
        """
        Run the full multi-agent swarm pipeline.

        Args:
            message: The raw text message
            classification: Result from existing ScamClassifier
            ssf_result: Result from existing SSFEngine

        Returns:
            MultiAgentResult with all agent outputs combined
        """
        # Build initial state
        initial_state: ScamState = {
            "message": message,
            "classification": {
                "is_scam": classification.is_scam,
                "confidence": classification.confidence,
                "scam_type": classification.scam_type,
                "reasoning": classification.reasoning,
            },
            "ssf_result": {
                "urgency_score": ssf_result.urgency_score,
                "authority_claims": ssf_result.authority_claims,
                "payment_escalation": ssf_result.payment_escalation,
            },
            "errors": [],
        }

        # Execute the graph
        try:
            final_state = await self._compiled.ainvoke(initial_state)
        except Exception as e:
            logger.error(f"AgentSwarm graph execution failed: {e}")
            # Return a degraded result
            return MultiAgentResult(
                psychological_analysis="Analysis unavailable due to error.",
                policy_analysis="Analysis unavailable due to error.",
                aggregated_scam_score=classification.confidence,
                suspected_reason=classification.reasoning,
                urgency_score=ssf_result.urgency_score,
                fear_score=0.0,
                authority_score=0.0,
                extracted_artifacts={},
                campaign_result={},
                errors=[str(e)],
            )

        # Extract results from final state
        cognitive = final_state.get("cognitive_profile", {})
        policy = final_state.get("policy_validation", {})

        return MultiAgentResult(
            psychological_analysis=cognitive.get(
                "psychological_analysis",
                "No emotional profile available."
            ),
            policy_analysis=policy.get(
                "policy_analysis",
                "No policy analysis available."
            ),
            aggregated_scam_score=final_state.get(
                "aggregated_scam_score",
                classification.confidence
            ),
            suspected_reason=final_state.get(
                "suspected_reason",
                classification.reasoning
            ),
            urgency_score=cognitive.get("urgency_score", ssf_result.urgency_score),
            fear_score=cognitive.get("fear_score", 0.0),
            authority_score=cognitive.get("authority_score", 0.0),
            extracted_artifacts=final_state.get("extracted_artifacts", {}),
            campaign_result=final_state.get("campaign_result", {}),
            errors=final_state.get("errors", []),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Utility: JSON parsing with resilience
# ─────────────────────────────────────────────────────────────────────────────

def _parse_json_response(text: str) -> Optional[Dict[str, Any]]:
    """Bulletproof JSON extractor for chatty LLMs."""
    if not text:
        return None

    try:
        # First, try to parse it directly in case it's already perfect
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass

    try:
        # Use regex to find the first '{' and the last '}'
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            clean_json_string = match.group(0)
            return json.loads(clean_json_string)
    except (json.JSONDecodeError, Exception):
        pass

    return None


def _heuristic_cognitive_profile(message: str) -> Dict[str, Any]:
    """Rule-based fallback for cognitive profiling when all LLMs fail."""
    msg_lower = message.lower()

    # Urgency heuristics
    urgency_keywords = [
        "urgent", "immediately", "act now", "expire", "deadline",
        "last chance", "final notice", "within 24 hours", "minutes",
        "hours left", "don't delay"
    ]
    urgency_hits = sum(1 for kw in urgency_keywords if kw in msg_lower)
    urgency_score = min(urgency_hits / 3.0, 1.0)

    # Fear heuristics
    fear_keywords = [
        "blocked", "suspended", "frozen", "arrested", "legal action",
        "fine", "penalty", "court", "police", "terminate", "close",
        "restricted", "unauthorized"
    ]
    fear_hits = sum(1 for kw in fear_keywords if kw in msg_lower)
    fear_score = min(fear_hits / 3.0, 1.0)

    # Authority heuristics
    authority_keywords = [
        "bank", "sbi", "rbi", "income tax", "police", "court",
        "government", "official", "authorized", "security team",
        "customer care", "cbi", "customs", "narcotics"
    ]
    authority_hits = sum(1 for kw in authority_keywords if kw in msg_lower)
    authority_score = min(authority_hits / 2.0, 1.0)

    analysis_parts = []
    if urgency_score > 0.5:
        analysis_parts.append("Artificial urgency pressure detected via time constraints")
    if fear_score > 0.5:
        analysis_parts.append("Fear-based manipulation through account/legal threats")
    if authority_score > 0.5:
        analysis_parts.append("Authority figure impersonation present")

    return {
        "fear_score": round(fear_score, 2),
        "urgency_score": round(urgency_score, 2),
        "authority_score": round(authority_score, 2),
        "psychological_analysis": ". ".join(analysis_parts) if analysis_parts
            else "No significant manipulation tactics detected via heuristic analysis."
    }


# ─────────────────────────────────────────────────────────────────────────────
# Singleton accessor
# ─────────────────────────────────────────────────────────────────────────────

_swarm_instance: Optional[AgentSwarm] = None


def get_agent_swarm() -> AgentSwarm:
    """Get the singleton AgentSwarm instance."""
    global _swarm_instance
    if _swarm_instance is None:
        _swarm_instance = AgentSwarm()
    return _swarm_instance
