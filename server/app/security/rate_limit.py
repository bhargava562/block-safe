"""
BlockSafe Rate Limiting
In-memory rate limiting for API protection
"""

import time
from typing import Dict, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from fastapi import HTTPException, Request, status, Depends
from app.security.auth import verify_api_key


@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_limit: int = 10


@dataclass
class RequestRecord:
    """Track requests for a client"""
    minute_requests: list = field(default_factory=list)
    hour_requests: list = field(default_factory=list)


class RateLimiter:
    """
    In-memory rate limiter.
    Note: For production, use Redis-based rate limiting.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._records: Dict[str, RequestRecord] = defaultdict(RequestRecord)

    def _cleanup_old_requests(self, record: RequestRecord, now: float) -> None:
        """Remove expired request timestamps"""
        minute_ago = now - 60
        hour_ago = now - 3600

        record.minute_requests = [
            t for t in record.minute_requests if t > minute_ago
        ]
        record.hour_requests = [
            t for t in record.hour_requests if t > hour_ago
        ]

    def check_rate_limit(self, client_id: str) -> None:
        """
        Check if client has exceeded rate limits.

        Args:
            client_id: Unique client identifier (e.g., API key or IP)

        Raises:
            HTTPException: 429 if rate limit exceeded
        """
        now = time.time()
        record = self._records[client_id]

        # Cleanup old requests
        self._cleanup_old_requests(record, now)

        # Check minute limit
        if len(record.minute_requests) >= self.config.requests_per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Max {self.config.requests_per_minute} requests per minute.",
                headers={"Retry-After": "60"}
            )

        # Check hour limit
        if len(record.hour_requests) >= self.config.requests_per_hour:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Max {self.config.requests_per_hour} requests per hour.",
                headers={"Retry-After": "3600"}
            )

        # Record this request
        record.minute_requests.append(now)
        record.hour_requests.append(now)

    def get_remaining(self, client_id: str) -> Dict[str, int]:
        """Get remaining requests for a client"""
        now = time.time()
        record = self._records[client_id]
        self._cleanup_old_requests(record, now)

        return {
            "minute_remaining": max(0, self.config.requests_per_minute - len(record.minute_requests)),
            "hour_remaining": max(0, self.config.requests_per_hour - len(record.hour_requests))
        }


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance"""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


# Dependency to enforce rate limiting per client
async def enforce_rate_limit(
    request: Request,
    api_key: str = Depends(verify_api_key)
) -> None:
    """Rate limit based on API key (preferred) or client host."""
    limiter = get_rate_limiter()
    client_id = api_key or request.client.host or "anonymous"
    limiter.check_rate_limit(client_id)
