"""
BlockSafe Multi-Agent Intelligence Layer
LangChain-powered parallel agents with automatic quota fallback.

Architecture:
  ┌──────────┐     ┌─────────────────────┐
  │ Message  │────▶│   LangChain Router  │
  └──────────┘     └────────┬────────────┘
                   ┌────────┴────────┐
            ┌──────▼──────┐  ┌───────▼───────┐
            │  Profiler   │  │ Fact-Checker   │
            │ (OpenAI)    │  │ (Gemini+Search)│
            └──────┬──────┘  └───────┬───────┘
                   │  .with_fallbacks([Groq])
            ┌──────▼─────────────────▼──────┐
            │     Merger → AgentAnalysis    │
            └───────────────────────────────┘
"""

import asyncio
from typing import Optional, List
from dataclasses import dataclass, field

from pydantic import BaseModel, Field

from app.config import get_settings
from app.utils.logger import logger


# ─────────────────────────────────────────────────────────────
# 1. PYDANTIC OUTPUT SCHEMAS (bound to LangChain structured output)
# ─────────────────────────────────────────────────────────────

class ProfilerOutput(BaseModel):
    """Output from the Cognitive Risk Profiler (Agent 1).
    Measures psychological pressure, NOT topic content."""

    urgency_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="Time-pressure level (deadlines, account closure threats)"
    )
    fear_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="Fear induction level (legal threats, arrest, account blocking)"
    )
    authority_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="Authority impersonation level (bank official, police, government)"
    )
    risk_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="Aggregated cognitive manipulation risk (0.0=safe, 1.0=maximum pressure)"
    )
    reasoning: str = Field(
        ...,
        description="Brief explanation of the psychological manipulation vectors detected"
    )


class FactCheckerOutput(BaseModel):
    """Output from the Real-Time Fact-Checker (Agent 2).
    Verifies claims against official sources via live search."""

    entity: Optional[str] = Field(
        None,
        description="The organization/entity mentioned (e.g., 'SBI Bank', 'RBI')"
    )
    claimed_action: Optional[str] = Field(
        None,
        description="What the message claims the entity requires (e.g., 'PAN update via SMS link')"
    )
    policy_violation: bool = Field(
        False,
        description="True if the claimed action contradicts known official policies"
    )
    verified_result: Optional[str] = Field(
        None,
        description="Fact-check finding (e.g., 'SBI never asks for KYC updates via SMS links')"
    )
    source_url: Optional[str] = Field(
        None,
        description="URL of the official source that contradicts the claim"
    )
    reasoning: str = Field(
        ...,
        description="Explanation of the fact-check analysis"
    )


# ─────────────────────────────────────────────────────────────
# 2. MERGED RESULT
# ─────────────────────────────────────────────────────────────

@dataclass
class AgentAnalysis:
    """Unified output after merging both agents."""
    # Profiler scores
    urgency_score: float = 0.0
    fear_score: float = 0.0
    authority_score: float = 0.0
    cognitive_risk_score: float = 0.0
    profiler_reasoning: str = ""

    # Fact-checker results
    entity: Optional[str] = None
    claimed_action: Optional[str] = None
    policy_violation: bool = False
    verified_result: Optional[str] = None
    source_url: Optional[str] = None
    fact_checker_reasoning: str = ""

    # Meta
    provider_used: str = "unknown"
    profiler_provider: str = "none"
    fact_checker_provider: str = "none"

    # Derived classification
    is_scam: bool = False
    confidence: float = 0.0
    scam_type: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# 3. PROMPT TEMPLATES
# ─────────────────────────────────────────────────────────────

PROFILER_SYSTEM = """You are a Cognitive Risk Profiler. Your job is to analyze the PSYCHOLOGICAL MANIPULATION in a message, NOT the topic.

You evaluate THREE behavioral vectors:
1. **Urgency** — Time limits, deadlines, "act now or else" pressure
2. **Fear Induction** — Threats of account closure, legal action, arrest, financial loss
3. **Authority Impersonation** — Pretending to be a bank, police, government, or other trusted institution

Score each vector from 0.0 (absent) to 1.0 (extreme).
Calculate risk_score as the weighted average: (urgency * 0.3) + (fear * 0.4) + (authority * 0.3)

A normal legitimate message (e.g., a friend asking to meet) should score near 0.0 on all vectors.
A scam message applying heavy psychological pressure should score near 1.0.

Be precise. Do not hallucinate threats that aren't in the text."""

PROFILER_HUMAN = "Analyze the psychological manipulation in this message:\n\n{message}"

FACT_CHECKER_SYSTEM = """You are a Real-Time Policy Fact-Checker. Your job is to verify whether claims made in a message about an organization are TRUE or FALSE.

Steps:
1. Extract the entity (bank, government body, company) mentioned in the message
2. Extract what action the message claims the entity requires (e.g., "update PAN via SMS link")
3. Determine if this claimed action contradicts known official policies

IMPORTANT RULES:
- If no specific organization is mentioned, set entity to null and policy_violation to false
- If the message is a normal conversation with no institutional claims, set all fields to null/false
- Only flag policy_violation=true when you have STRONG evidence the claim contradicts official policy
- Common violations: banks never ask for OTP/PIN via SMS, RBI never calls directly, police don't demand payment via UPI

Be conservative. Only flag true violations."""

FACT_CHECKER_HUMAN = "Fact-check the institutional claims in this message:\n\n{message}"


# ─────────────────────────────────────────────────────────────
# 4. CHAIN BUILDERS (lazy, cached)
# ─────────────────────────────────────────────────────────────

_profiler_chain = None
_fact_checker_chain = None
_chains_initialized = False
_init_lock = None


def _get_init_lock():
    """Lazy-init the asyncio lock (must be created inside a running event loop)."""
    global _init_lock
    if _init_lock is None:
        _init_lock = asyncio.Lock()
    return _init_lock


def _build_profiler_chain():
    """Build OpenAI profiler chain with Groq fallback."""
    settings = get_settings()

    from langchain_core.prompts import ChatPromptTemplate

    prompt = ChatPromptTemplate.from_messages([
        ("system", PROFILER_SYSTEM),
        ("human", PROFILER_HUMAN),
    ])

    # Primary: OpenAI gpt-4o-mini
    primary = None
    if settings.has_openai:
        try:
            from langchain_openai import ChatOpenAI
            primary = ChatOpenAI(
                model=settings.OPENAI_MODEL,
                api_key=settings.OPENAI_API_KEY.get_secret_value(),
                temperature=0.0,
                max_tokens=512,
                request_timeout=settings.AGENT_TIMEOUT_SECONDS,
            )
            logger.info(f"Profiler primary: OpenAI ({settings.OPENAI_MODEL})")
        except Exception as e:
            logger.warning(f"Failed to init OpenAI profiler: {e}")

    # Fallback to Gemini if OpenAI unavailable
    gemini_fallback = None
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        gemini_fallback = ChatGoogleGenerativeAI(
            model=settings.GEMINI_MODEL,
            google_api_key=settings.GEMINI_API_KEY.get_secret_value(),
            temperature=0.0,
            max_output_tokens=512,
        )
        logger.info(f"Profiler gemini fallback: {settings.GEMINI_MODEL}")
    except Exception as e:
        logger.warning(f"Failed to init Gemini profiler fallback: {e}")

    # Groq fallback (open-source, high availability)
    groq_fallback = None
    if settings.has_groq:
        try:
            from langchain_groq import ChatGroq
            groq_fallback = ChatGroq(
                model=settings.GROQ_MODEL,
                api_key=settings.GROQ_API_KEY.get_secret_value(),
                temperature=0.0,
                max_tokens=512,
                request_timeout=settings.AGENT_TIMEOUT_SECONDS,
            )
            logger.info(f"Profiler groq fallback: {settings.GROQ_MODEL}")
        except Exception as e:
            logger.warning(f"Failed to init Groq profiler fallback: {e}")

    # Pick the best available primary
    if primary is None:
        primary = gemini_fallback
        gemini_fallback = None  # Don't use same model as both primary and fallback

    if primary is None:
        primary = groq_fallback
        groq_fallback = None

    if primary is None:
        logger.error("No AI provider available for profiler!")
        return None

    # Bind structured output
    structured = primary.with_structured_output(ProfilerOutput)

    # Build fallback chain
    fallbacks = []
    if gemini_fallback:
        fallbacks.append(gemini_fallback.with_structured_output(ProfilerOutput))
    if groq_fallback:
        fallbacks.append(groq_fallback.with_structured_output(ProfilerOutput))

    if fallbacks:
        structured = structured.with_fallbacks(fallbacks)

    return prompt | structured


def _build_fact_checker_chain():
    """Build Gemini fact-checker chain with search grounding and Groq fallback."""
    settings = get_settings()

    from langchain_core.prompts import ChatPromptTemplate

    prompt = ChatPromptTemplate.from_messages([
        ("system", FACT_CHECKER_SYSTEM),
        ("human", FACT_CHECKER_HUMAN),
    ])

    # Primary: Gemini with search grounding
    primary = None
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        primary = ChatGoogleGenerativeAI(
            model=settings.GEMINI_MODEL,
            google_api_key=settings.GEMINI_API_KEY.get_secret_value(),
            temperature=0.0,
            max_output_tokens=512,
        )
        logger.info(f"Fact-checker primary: Gemini ({settings.GEMINI_MODEL})")
    except Exception as e:
        logger.warning(f"Failed to init Gemini fact-checker: {e}")

    # OpenAI fallback
    openai_fallback = None
    if settings.has_openai:
        try:
            from langchain_openai import ChatOpenAI
            openai_fallback = ChatOpenAI(
                model=settings.OPENAI_MODEL,
                api_key=settings.OPENAI_API_KEY.get_secret_value(),
                temperature=0.0,
                max_tokens=512,
                request_timeout=settings.AGENT_TIMEOUT_SECONDS,
            )
            logger.info(f"Fact-checker openai fallback: {settings.OPENAI_MODEL}")
        except Exception as e:
            logger.warning(f"Failed to init OpenAI fact-checker fallback: {e}")

    # Groq fallback
    groq_fallback = None
    if settings.has_groq:
        try:
            from langchain_groq import ChatGroq
            groq_fallback = ChatGroq(
                model=settings.GROQ_MODEL,
                api_key=settings.GROQ_API_KEY.get_secret_value(),
                temperature=0.0,
                max_tokens=512,
                request_timeout=settings.AGENT_TIMEOUT_SECONDS,
            )
            logger.info(f"Fact-checker groq fallback: {settings.GROQ_MODEL}")
        except Exception as e:
            logger.warning(f"Failed to init Groq fact-checker fallback: {e}")

    if primary is None:
        primary = openai_fallback
        openai_fallback = None

    if primary is None:
        primary = groq_fallback
        groq_fallback = None

    if primary is None:
        logger.error("No AI provider available for fact-checker!")
        return None

    # Bind structured output
    structured = primary.with_structured_output(FactCheckerOutput)

    # Build fallback chain
    fallbacks = []
    if openai_fallback:
        fallbacks.append(openai_fallback.with_structured_output(FactCheckerOutput))
    if groq_fallback:
        fallbacks.append(groq_fallback.with_structured_output(FactCheckerOutput))

    if fallbacks:
        structured = structured.with_fallbacks(fallbacks)

    return prompt | structured


# ─────────────────────────────────────────────────────────────
# 5. INITIALIZATION
# ─────────────────────────────────────────────────────────────

async def _ensure_chains():
    """Lazy-init chains on first call (thread-safe)."""
    global _profiler_chain, _fact_checker_chain, _chains_initialized

    if _chains_initialized:
        return

    async with _get_init_lock():
        if _chains_initialized:
            return

        logger.info("Initializing multi-agent chains...")
        _profiler_chain = _build_profiler_chain()
        _fact_checker_chain = _build_fact_checker_chain()
        _chains_initialized = True
        logger.info(
            f"Multi-agent chains ready: "
            f"profiler={'OK' if _profiler_chain else 'UNAVAILABLE'}, "
            f"fact_checker={'OK' if _fact_checker_chain else 'UNAVAILABLE'}"
        )


# ─────────────────────────────────────────────────────────────
# 6. PARALLEL EXECUTION
# ─────────────────────────────────────────────────────────────

async def _run_profiler(message: str) -> tuple[Optional[ProfilerOutput], str]:
    """Run profiler agent, return (output, provider_name)."""
    if _profiler_chain is None:
        return None, "none"

    try:
        result = await _profiler_chain.ainvoke({"message": message})
        # Determine which provider actually handled it
        provider = "openai_primary"
        if not get_settings().has_openai:
            provider = "gemini_primary"
        return result, provider
    except Exception as e:
        # If primary + all fallbacks failed, check if Groq caught it
        if "groq" in str(e).lower() or "fallback" in str(e).lower():
            provider = "groq_fallback_triggered"
        else:
            provider = "fallback_exhausted"
        logger.error(f"Profiler failed after all fallbacks: {e}")
        return None, provider


async def _run_fact_checker(message: str) -> tuple[Optional[FactCheckerOutput], str]:
    """Run fact-checker agent, return (output, provider_name)."""
    if _fact_checker_chain is None:
        return None, "none"

    try:
        result = await _fact_checker_chain.ainvoke({"message": message})
        provider = "gemini_search_grounding"
        return result, provider
    except Exception as e:
        logger.error(f"Fact-checker failed after all fallbacks: {e}")
        return None, "fallback_exhausted"


async def run_agents(message: str) -> AgentAnalysis:
    """
    Run Profiler + Fact-Checker in parallel with automatic fallback.

    This is the main entry point called by scam_detector.classify().
    Returns a merged AgentAnalysis with cognitive scores and policy verification.
    """
    settings = get_settings()
    await _ensure_chains()

    analysis = AgentAnalysis()

    # Run both agents concurrently
    try:
        timeout = settings.AGENT_TIMEOUT_SECONDS
        (profiler_result, profiler_provider), (fc_result, fc_provider) = await asyncio.wait_for(
            asyncio.gather(
                _run_profiler(message),
                _run_fact_checker(message),
                return_exceptions=False,
            ),
            timeout=timeout + 5,  # slight buffer over per-agent timeout
        )
    except asyncio.TimeoutError:
        logger.error(f"Agent orchestration timed out after {settings.AGENT_TIMEOUT_SECONDS + 5}s")
        analysis.provider_used = "timeout"
        return analysis
    except Exception as e:
        logger.error(f"Agent orchestration error: {e}")
        analysis.provider_used = "error"
        return analysis

    # ── Merge Profiler results ──────────────────────────────
    analysis.profiler_provider = profiler_provider
    if profiler_result is not None:
        analysis.urgency_score = profiler_result.urgency_score
        analysis.fear_score = profiler_result.fear_score
        analysis.authority_score = profiler_result.authority_score
        analysis.cognitive_risk_score = profiler_result.risk_score
        analysis.profiler_reasoning = profiler_result.reasoning

    # ── Merge Fact-Checker results ──────────────────────────
    analysis.fact_checker_provider = fc_provider
    if fc_result is not None:
        analysis.entity = fc_result.entity
        analysis.claimed_action = fc_result.claimed_action
        analysis.policy_violation = fc_result.policy_violation
        analysis.verified_result = fc_result.verified_result
        analysis.source_url = fc_result.source_url
        analysis.fact_checker_reasoning = fc_result.reasoning

    # ── Derive classification from agent outputs ────────────
    risk = analysis.cognitive_risk_score
    threshold = settings.COGNITIVE_RISK_THRESHOLD

    if risk >= threshold or analysis.policy_violation:
        analysis.is_scam = True
        # Boost confidence if policy violation confirms the scam
        base_conf = min(risk, 1.0)
        if analysis.policy_violation:
            base_conf = max(base_conf, 0.90)
        analysis.confidence = round(base_conf, 2)

        # Determine scam type from authority/fear signals
        if analysis.authority_score >= 0.7:
            if analysis.entity and "bank" in (analysis.entity or "").lower():
                analysis.scam_type = "bank_impersonation"
            elif analysis.entity and any(g in (analysis.entity or "").lower() for g in ["police", "rbi", "government", "court"]):
                analysis.scam_type = "government_impersonation"
            else:
                analysis.scam_type = "authority_impersonation"
        elif analysis.fear_score >= 0.7:
            analysis.scam_type = "phishing"
        elif analysis.urgency_score >= 0.7:
            analysis.scam_type = "upi_fraud"
        else:
            analysis.scam_type = "social_engineering"
    else:
        analysis.is_scam = False
        analysis.confidence = round(1.0 - risk, 2)  # confidence it's NOT a scam
        analysis.scam_type = None

    # ── Composite provider tag ──────────────────────────────
    if "fallback" in profiler_provider or "fallback" in fc_provider:
        analysis.provider_used = "groq_fallback_triggered"
    else:
        providers = set()
        if "openai" in profiler_provider:
            providers.add("openai")
        if "gemini" in profiler_provider or "gemini" in fc_provider:
            providers.add("gemini")
        if "groq" in profiler_provider or "groq" in fc_provider:
            providers.add("groq")
        analysis.provider_used = "_".join(sorted(providers)) + "_primary" if providers else "unknown"

    logger.info(
        f"Agent analysis complete: is_scam={analysis.is_scam}, "
        f"risk={analysis.cognitive_risk_score:.2f}, "
        f"policy_violation={analysis.policy_violation}, "
        f"provider={analysis.provider_used}"
    )

    return analysis
