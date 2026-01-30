"""
BlockSafe Dependencies
Shared FastAPI dependencies
"""

from typing import Annotated

from fastapi import Depends

from app.config import Settings, get_settings
from app.security.auth import verify_api_key


# Type aliases for common dependencies
SettingsDep = Annotated[Settings, Depends(get_settings)]
AuthDep = Annotated[str, Depends(verify_api_key)]
