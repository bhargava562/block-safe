"""
BlockSafe Intelligence Agents  
Declarative multi-agent classification pipeline with high-availability fallbacks.

Pipeline 1 (Profiler):
  - Primary: Groq llama-3.3-70b
  - Fallback: DeepSeek deepseek-chat

Pipeline 2 (Fact-Checker):
  - Primary: Groq llama-3.3-70b
  - Fallback: DeepSeek deepseek-chat
"""

import asyncio
from typing import Optional, List
from pydantic import BaseModel, Field

from app.config import get_settings
from app.utils.logger import logger

# ─── Structured Output Schemas ──────────────────────────────────────────

class ProfilerOutput(BaseModel):
    """Structured output for psychological manipulation analysis."""
    fear_score: float = Field(..., description="Intensity of fear induction (0-1)")
    urgency_score: float = Field(..., description="Intensity of artificial urgency (0-1)")
    authority_score: float = Field(..., description="Intensity of authority impersonation (0-1)")
    psychological_analysis: str = Field(..., description="Description of manipulation tactics found")

class FactCheckerOutput(BaseModel):
    """Structured output for policy and entity verification."""
    entity: Optional[str] = Field(None, description="The organization or person being impersonated")
    claimed_action: Optional[str] = Field(None, description="What the message asks the user to do")
    policy_violation: bool = Field(False, description="True if the action violates known safety policies")
    verified_result: Optional[str] = Field(None, description="Explanation of why this is or isn't a violation")
    fact_checker_analysis: str = Field(..., description="Summary of the policy verification process")

class AgentAnalysis(BaseModel):
    """Merged output from Profiler + Fact-Checker agents."""
    is_scam: bool = False
    confidence: float = 0.0
    scam_type: Optional[str] = None
    provider_used: str = "multi_agent_pipeline"

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
    fact_checker_reasoning: str = ""

# ─── Agent Chains (Declarative) ────────────────────────────────────────

def _get_profiler_chain():
    """Builds the profiler fallback chain (Groq Primary)."""
    settings = get_settings()
    
    # 1. Groq (Primary)
    from langchain_groq import ChatGroq
    groq_llm = ChatGroq(
        model=settings.GROQ_MODEL,
        api_key=settings.GROQ_API_KEY.get_secret_value() if settings.has_groq else "dummy",
        temperature=0.1,
        max_tokens=512,
        request_timeout=settings.AGENT_TIMEOUT_SECONDS,
        max_retries=1
    )
    
    # 2. DeepSeek (Fallback)
    from langchain_openai import ChatOpenAI
    deepseek_llm = ChatOpenAI(
        model=settings.DEEPSEEK_MODEL,
        api_key=settings.DEEPSEEK_API_KEY.get_secret_value() if settings.has_deepseek else "dummy",
        base_url="https://api.deepseek.com",
        temperature=0.1,
        max_tokens=512,
        request_timeout=settings.AGENT_TIMEOUT_SECONDS,
        max_retries=1
    )
    
    # Bind structured output
    groq_struct = groq_llm.with_structured_output(ProfilerOutput)
    deepseek_struct = deepseek_llm.with_structured_output(ProfilerOutput)
    
    # Define fallback sequence
    fallbacks = []
    if settings.has_deepseek: fallbacks.append(deepseek_struct)
    
    return groq_struct.with_fallbacks(fallbacks)

def _get_fact_checker_chain():
    """Builds the fact-checker fallback chain (Groq Primary)."""
    settings = get_settings()
    
    # 1. Groq (Primary)
    from langchain_groq import ChatGroq
    groq_llm = ChatGroq(
        model=settings.GROQ_MODEL,
        api_key=settings.GROQ_API_KEY.get_secret_value() if settings.has_groq else "dummy",
        temperature=0.1,
        max_tokens=512,
        request_timeout=settings.AGENT_TIMEOUT_SECONDS,
        max_retries=1
    )
    
    # 2. DeepSeek (Fallback)
    from langchain_openai import ChatOpenAI
    deepseek_llm = ChatOpenAI(
        model=settings.DEEPSEEK_MODEL,
        api_key=settings.DEEPSEEK_API_KEY.get_secret_value() if settings.has_deepseek else "dummy",
        base_url="https://api.deepseek.com",
        temperature=0.1,
        max_tokens=512,
        request_timeout=settings.AGENT_TIMEOUT_SECONDS,
        max_retries=1
    )

    # Bind structured output
    groq_struct = groq_llm.with_structured_output(FactCheckerOutput)
    deepseek_struct = deepseek_llm.with_structured_output(FactCheckerOutput)
    
    fallbacks = []
    if settings.has_deepseek: fallbacks.append(deepseek_struct)
    
    return groq_struct.with_fallbacks(fallbacks)

# ─── Orchestrator ──────────────────────────────────────────────────────

async def run_agents(message: str) -> AgentAnalysis:
    """
    Execute Profiler + Fact-Checker in parallel using declarative fallback chains.
    """
    settings = get_settings()
    
    profiler_chain = _get_profiler_chain()
    fact_checker_chain = _get_fact_checker_chain()
    
    # Prompts
    profiler_prompt = (
        "Analyze the psychological tactics in this message. "
        "Ignore facts, focus on fear, urgency, and authority impersonation.\n\n"
        f"Message: {message}"
    )
    
    fact_checker_prompt = (
        "Analyze the policy validity of this message. "
        "Identify the claimed entity and the action they require. "
        "Assess if this violates official banking or safety policies.\n\n"
        f"Message: {message}"
    )

    try:
        # Run concurrently
        results = await asyncio.gather(
            profiler_chain.ainvoke(profiler_prompt) if profiler_chain else None,
            fact_checker_chain.ainvoke(fact_checker_prompt) if fact_checker_chain else None,
            return_exceptions=True
        )
        
        profiler_res, fact_checker_res = results
        
        # Handle exceptions in results
        if isinstance(profiler_res, Exception):
            logger.error(f"Profiler pipeline failed: {profiler_res}")
            profiler_res = ProfilerOutput(
                fear_score=0.0, urgency_score=0.0, authority_score=0.0, 
                psychological_analysis="Backup analysis failed."
            )
            
        if isinstance(fact_checker_res, Exception):
            logger.error(f"Fact-Checker pipeline failed: {fact_checker_res}")
            fact_checker_res = FactCheckerOutput(
                policy_violation=False, fact_checker_analysis="Backup analysis failed."
            )

        # ── Merge Results ───────────────────────────────────────────
        
        fear = profiler_res.fear_score if profiler_res else 0.0
        urgency = profiler_res.urgency_score if profiler_res else 0.0
        authority = profiler_res.authority_score if profiler_res else 0.0
        cognitive_risk = round((fear + urgency + authority) / 3, 2)
        
        policy_violation = fact_checker_res.policy_violation if fact_checker_res else False
        
        # ── Derive scam classification ──────────────────────────────
        risk_threshold = settings.COGNITIVE_RISK_THRESHOLD
        is_scam = cognitive_risk >= risk_threshold or policy_violation
        confidence = cognitive_risk
        
        if policy_violation:
            confidence = max(confidence, 0.85)
        if cognitive_risk >= 0.8 and policy_violation:
            confidence = 0.95
            
        confidence = round(min(confidence, 1.0), 2)
        
        # Scam type inference
        entity = fact_checker_res.entity if fact_checker_res else None
        scam_type = "phishing"
        if is_scam and entity:
            ent_lower = entity.lower()
            if any(kw in ent_lower for kw in ["bank", "sbi", "hdfc", "icici"]):
                scam_type = "bank_impersonation"
            elif any(kw in ent_lower for kw in ["rbi", "police", "court"]):
                scam_type = "government_impersonation"

        return AgentAnalysis(
            is_scam=is_scam,
            confidence=confidence,
            scam_type=scam_type,
            urgency_score=urgency,
            fear_score=fear,
            authority_score=authority,
            cognitive_risk_score=cognitive_risk,
            profiler_reasoning=profiler_res.psychological_analysis if profiler_res else "",
            policy_violation=policy_violation,
            entity=entity,
            claimed_action=fact_checker_res.claimed_action if fact_checker_res else None,
            verified_result=fact_checker_res.verified_result if fact_checker_res else None,
            fact_checker_reasoning=fact_checker_res.fact_checker_analysis if fact_checker_res else "",
        )

    except Exception as e:
        logger.error(f"Agent orchestration fatal error: {e}")
        # Return empty safe result
        return AgentAnalysis(provider_used="error_fallback")
