"""
BlockSafe Authentication Module
API key verification with secure comparison
"""

import hmac
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.config import Settings, get_settings

# API Key header scheme
api_key_header = APIKeyHeader(
    name="X-API-KEY",
    auto_error=True,
    description="API authentication key"
)


def verify_api_key(
    api_key: Annotated[str, Security(api_key_header)],
    settings: Annotated[Settings, Depends(get_settings)]
) -> str:
    """
    Verify the API key from request header.
    Uses constant-time comparison to prevent timing attacks.

    Args:
        api_key: The API key from X-API-KEY header
        settings: Application settings

    Returns:
        The verified API key

    Raises:
        HTTPException: 401 if key is invalid
    """
    expected_key = settings.API_AUTH_KEY.get_secret_value()

    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(api_key.encode(), expected_key.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    return api_key


# Dependency for protected routes
APIKeyDep = Annotated[str, Depends(verify_api_key)]
