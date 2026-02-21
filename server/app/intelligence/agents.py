"""
BlockSafe Intelligence Agents  
LangChain-based multi-agent classification pipeline.

Profiler Agent  → OpenAI gpt-4o-mini (fallback: Groq llama-3.3-70b)
Fact-Checker    → Gemini (fallback: Groq llama-3.3-70b)

Both agents run in parallel via asyncio.gather().
Results merge into AgentAnalysis consumed by scam_detector.ClassificationResult.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional

from app.config import get_settings
from app.utils.logger import logger


# ─── Result Dataclass ──────────────────────────────────────────────────

@dataclass
class AgentAnalysis:
    """Merged output from Profiler + Fact-Checker agents."""
    is_scam: bool = False
    confidence: float = 0.0
    scam_type: Optional[str] = None
    provider_used: str = "rule_based"

    # Profiler scores
    urgency_score: float = 0.0
    fear_score: float = 0.0
    authority_score: float = 0.0
    cognitive_risk_score: float = 0.0
    profiler_reasoning: str = ""

    # Fact-Checker outputs
    policy_violation: bool = False
    entity: Optional[str] = None
    claimed_action: Optional[str] = None
    verified_result: Optional[str] = None
    source_url: Optional[str] = None
    fact_checker_reasoning: str = ""


# ─── JSON Parser ───────────────────────────────────────────────────────

def _parse_json_safely(text: str) -> dict:
    """Extract and parse JSON from LLM responses, tolerating markdown fences."""
    if not text:
        return {}
    # Strip markdown code fences
    cleaned = re.sub(r"```(?:json)?\s*", "", text)
    cleaned = cleaned.strip().rstrip("`")
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Try to find JSON object in the text
        match = re.search(r"\{[^{}]*\}", cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
    return {}


# ─── Profiler Agent ────────────────────────────────────────────────────

_PROFILER_SYSTEM_PROMPT = (
    "You are a Cognitive Threat Analyst. Ignore the factual claims of the message. "
    "Your ONLY job is to detect psychological pressure: urgency, fear induction, and "
    "authority impersonation.\n\n"
    "Output STRICTLY valid JSON with these keys:\n"
    '{"fear_score": 0.0-1.0, "urgency_score": 0.0-1.0, "authority_score": 0.0-1.0, '
    '"psychological_analysis": "string explaining manipulation tactics"}'
)


async def _run_profiler(message: str) -> dict:
    """
    Cognitive risk profiler using OpenAI gpt-4o-mini → Groq llama fallback.
    Returns dict with fear_score, urgency_score, authority_score, psychological_analysis.
    """
    settings = get_settings()
    messages = [
        {"role": "system", "content": _PROFILER_SYSTEM_PROMPT},
        {"role": "user", "content": f"Analyze this message:\n\n{message}"},
    ]

    # Try OpenAI first
    if settings.has_openai:
        try:
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(
                model=settings.OPENAI_MODEL,
                api_key=settings.OPENAI_API_KEY.get_secret_value(),
                temperature=0.1,
                max_tokens=512,
                request_timeout=settings.AGENT_TIMEOUT_SECONDS,
            )
            response = await llm.ainvoke(messages)
            result = _parse_json_safely(response.content)
            if result:
                result["_provider"] = "openai"
                logger.info("Profiler: OpenAI success")
                return result
        except Exception as e:
            logger.warning(f"Profiler: OpenAI failed ({e}), falling back to Groq")

    # Groq fallback
    if settings.has_groq:
        try:
            from langchain_groq import ChatGroq

            llm = ChatGroq(
                model=settings.GROQ_MODEL,
                api_key=settings.GROQ_API_KEY.get_secret_value(),
                temperature=0.1,
                max_tokens=512,
                request_timeout=settings.AGENT_TIMEOUT_SECONDS,
            )
            response = await llm.ainvoke(messages)
            result = _parse_json_safely(response.content)
            if result:
                result["_provider"] = "groq_fallback"
                logger.info("Profiler: Groq fallback success")
                return result
        except Exception as e:
            logger.error(f"Profiler: Groq fallback also failed ({e})")

    # Heuristic fallback
    return _heuristic_profiler(message)


def _heuristic_profiler(message: str) -> dict:
    """Rule-based fallback when all LLM providers fail."""
    text_lower = message.lower()
    urgency = 0.0
    fear = 0.0
    authority = 0.0

    urgency_words = ["immediately", "urgent", "right now", "act now", "hurry", "limited time", "asap"]
    fear_words = ["blocked", "suspended", "frozen", "arrest", "legal action", "lawsuit", "seized"]
    authority_words = ["bank", "rbi", "police", "government", "sbi", "hdfc", "icici", "ministry"]

    for word in urgency_words:
        if word in text_lower:
            urgency += 0.2
    for word in fear_words:
        if word in text_lower:
            fear += 0.2
    for word in authority_words:
        if word in text_lower:
            authority += 0.25

    return {
        "fear_score": min(fear, 1.0),
        "urgency_score": min(urgency, 1.0),
        "authority_score": min(authority, 1.0),
        "psychological_analysis": "Heuristic analysis (AI providers unavailable)",
        "_provider": "heuristic",
    }


# ─── Fact-Checker Agent ───────────────────────────────────────────────

_FACT_CHECKER_SYSTEM_PROMPT = (
    "You are a Policy Fact-Checker. Given a message, identify the main claimed entity "
    "(e.g., 'SBI Bank', 'RBI') and the action they claim to require (e.g., 'account KYC update'). "
    "Then assess if such a policy actually exists using your knowledge.\n\n"
    "Output STRICTLY valid JSON with these keys:\n"
    '{"entity": "string or null", "claimed_action": "string or null", '
    '"policy_violation": true/false, "verified_result": "string explanation", '
    '"fact_checker_analysis": "string summary"}'
)


async def _run_fact_checker(message: str) -> dict:
    """
    Policy fact-checker using Gemini → Groq fallback.
    Returns dict with entity, claimed_action, policy_violation, verified_result.
    """
    settings = get_settings()
    messages = [
        {"role": "system", "content": _FACT_CHECKER_SYSTEM_PROMPT},
        {"role": "user", "content": f"Check this message:\n\n{message}"},
    ]

    # Try Gemini first
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI

        llm = ChatGoogleGenerativeAI(
            model=settings.GEMINI_MODEL,
            google_api_key=settings.GEMINI_API_KEY.get_secret_value(),
            temperature=0.1,
            max_output_tokens=512,
            request_timeout=settings.AGENT_TIMEOUT_SECONDS,
        )
        response = await llm.ainvoke(messages)
        result = _parse_json_safely(response.content)
        if result:
            result["_provider"] = "gemini"
            logger.info("FactChecker: Gemini success")
            return result
    except Exception as e:
        logger.warning(f"FactChecker: Gemini failed ({e}), falling back to Groq")

    # Groq fallback
    if settings.has_groq:
        try:
            from langchain_groq import ChatGroq

            llm = ChatGroq(
                model=settings.GROQ_MODEL,
                api_key=settings.GROQ_API_KEY.get_secret_value(),
                temperature=0.1,
                max_tokens=512,
                request_timeout=settings.AGENT_TIMEOUT_SECONDS,
            )
            response = await llm.ainvoke(messages)
            result = _parse_json_safely(response.content)
            if result:
                result["_provider"] = "groq_fallback"
                logger.info("FactChecker: Groq fallback success")
                return result
        except Exception as e:
            logger.error(f"FactChecker: Groq fallback also failed ({e})")

    return {"policy_violation": False, "verified_result": None, "_provider": "none"}


# ─── Orchestrator ──────────────────────────────────────────────────────

async def run_agents(message: str) -> AgentAnalysis:
    """
    Execute Profiler + Fact-Checker in parallel and merge into AgentAnalysis.

    Called by scam_detector.ScamClassifier.classify() as the first classification
    attempt. Falls through to legacy Gemini if this raises.
    """
    settings = get_settings()

    # Run both agents concurrently with individual timeouts
    timeout = settings.AGENT_TIMEOUT_SECONDS + 5  # buffer on top of per-agent timeout

    try:
        profiler_result, fact_checker_result = await asyncio.wait_for(
            asyncio.gather(
                _run_profiler(message),
                _run_fact_checker(message),
                return_exceptions=True,
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.error(f"Agent orchestration timed out after {timeout}s")
        raise RuntimeError("Agent orchestration timed out")

    # Handle individual agent failures
    if isinstance(profiler_result, Exception):
        logger.error(f"Profiler agent raised: {profiler_result}")
        profiler_result = _heuristic_profiler(message)
    if isinstance(fact_checker_result, Exception):
        logger.error(f"FactChecker agent raised: {fact_checker_result}")
        fact_checker_result = {"policy_violation": False, "_provider": "none"}

    # ── Merge into AgentAnalysis ────────────────────────────────────
    fear = float(profiler_result.get("fear_score", 0.0))
    urgency = float(profiler_result.get("urgency_score", 0.0))
    authority = float(profiler_result.get("authority_score", 0.0))
    cognitive_risk = round((fear + urgency + authority) / 3, 2)

    policy_violation = bool(fact_checker_result.get("policy_violation", False))
    entity = fact_checker_result.get("entity")
    claimed_action = fact_checker_result.get("claimed_action")
    verified_result = fact_checker_result.get("verified_result")

    # ── Derive scam classification ──────────────────────────────────
    risk_threshold = settings.COGNITIVE_RISK_THRESHOLD
    is_scam = cognitive_risk >= risk_threshold or policy_violation
    confidence = cognitive_risk

    if policy_violation:
        confidence = max(confidence, 0.85)
    if cognitive_risk >= 0.8 and policy_violation:
        confidence = 0.95

    confidence = round(min(confidence, 1.0), 2)

    # Infer scam_type from the entity/claiming pattern
    scam_type = None
    if is_scam:
        if entity:
            entity_lower = entity.lower()
            if any(kw in entity_lower for kw in ["bank", "sbi", "hdfc", "icici", "axis"]):
                scam_type = "bank_impersonation"
            elif any(kw in entity_lower for kw in ["rbi", "reserve"]):
                scam_type = "government_impersonation"
            elif any(kw in entity_lower for kw in ["police", "court", "arrest"]):
                scam_type = "government_impersonation"
            else:
                scam_type = "phishing"
        else:
            scam_type = "phishing"

    # ── Provider tracking ───────────────────────────────────────────
    profiler_provider = profiler_result.get("_provider", "unknown")
    fact_checker_provider = fact_checker_result.get("_provider", "unknown")
    provider_used = f"{profiler_provider}+{fact_checker_provider}"

    analysis = AgentAnalysis(
        is_scam=is_scam,
        confidence=confidence,
        scam_type=scam_type,
        provider_used=provider_used,
        urgency_score=urgency,
        fear_score=fear,
        authority_score=authority,
        cognitive_risk_score=cognitive_risk,
        profiler_reasoning=profiler_result.get("psychological_analysis", ""),
        policy_violation=policy_violation,
        entity=entity,
        claimed_action=claimed_action,
        verified_result=verified_result,
        fact_checker_reasoning=fact_checker_result.get("fact_checker_analysis", ""),
    )

    logger.info(
        f"AgentAnalysis: is_scam={analysis.is_scam} confidence={analysis.confidence} "
        f"risk={analysis.cognitive_risk_score} policy_violation={analysis.policy_violation} "
        f"provider={analysis.provider_used}"
    )
    return analysis
