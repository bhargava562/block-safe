"""
BlockSafe Intelligence Agents
LangChain chain initialization for multi-agent classification pipeline.

Uses lazy asyncio.Lock initialization to avoid Python 3.10+ deprecation
warnings when no event loop is running at import time.
"""

import asyncio
from typing import Optional

from app.utils.logger import logger


# Lazy-initialized lock — NOT created at module level to avoid
# "no current event loop" DeprecationWarning in Python 3.10+
_init_lock: Optional[asyncio.Lock] = None
_chains_initialized: bool = False


def _get_init_lock() -> asyncio.Lock:
    """Lazy-init the asyncio lock (must be created inside a running event loop)."""
    global _init_lock
    if _init_lock is None:
        _init_lock = asyncio.Lock()
    return _init_lock


async def _ensure_chains() -> None:
    """
    Ensure LangChain chains are initialized exactly once.
    Uses a lazy lock to avoid creating asyncio primitives at import time.
    """
    global _chains_initialized
    if _chains_initialized:
        return

    async with _get_init_lock():
        # Double-check after acquiring the lock
        if _chains_initialized:
            return

        try:
            logger.info("Intelligence agents: initializing chains")
            # Chains are built on-demand by agent_swarm sub-agents;
            # this module exposes the initialization guard only.
            _chains_initialized = True
            logger.info("Intelligence agents: chains ready")
        except Exception as e:
            logger.error(f"Intelligence agents: chain initialization failed: {e}")
            raise
