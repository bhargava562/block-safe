import asyncio
from typing import List, Optional, Dict, Any
from supabase import create_client, Client
from app.config import get_settings
from app.utils.logger import logger

class DatabaseManager:
    """
    Singleton manager for Supabase interactions.
    Provides async-safe database persistence for honeypot sessions and messages.
    """
    _instance: Optional["DatabaseManager"] = None
    _client: Optional[Client] = None

    def __new__(cls) -> "DatabaseManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._client is None:
            self._connect()

    def _connect(self):
        """Initialize the Supabase client."""
        settings = get_settings()
        if not settings.has_supabase:
            logger.warning("Supabase credentials missing. Database operations will be disabled.")
            return

        try:
            self._client = create_client(
                settings.SUPABASE_URL,
                settings.SUPABASE_SERVICE_KEY.get_secret_value()
            )
            logger.info("Supabase client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Supabase client: {e}")

    @property
    def is_ready(self) -> bool:
        return self._client is not None

    async def create_session(
        self,
        session_id: str,
        campaign_id: Optional[str],
        scam_type: str,
        confidence: float,
        initial_message: Optional[str] = None
    ):
        """Create a new scam session in the DB asynchronously."""
        if not self.is_ready:
            return

        def _insert():
            data = {
                "id": session_id,
                "campaign_id": campaign_id,
                "scam_type": scam_type,
                "confidence_score": confidence,
                "status": "active",
                "turns_completed": 0,
                "initial_message": initial_message
            }
            return self._client.table("scam_sessions").insert(data).execute()

        try:
            await asyncio.to_thread(_insert)
        except Exception as e:
            logger.error(f"DB Error (create_session): {e}")

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Fetch session metadata asynchronously."""
        if not self.is_ready:
            return None

        def _select():
            return self._client.table("scam_sessions").select("*").eq("id", session_id).execute()

        try:
            response = await asyncio.to_thread(_select)
            if response and response.data:
                return response.data[0]
        except Exception as e:
            logger.error(f"DB Error (get_session): {e}")
        return None

    async def get_history(self, session_id: str, limit: int = 6) -> List[Dict[str, Any]]:
        """Retrieve last N messages for context asynchronously."""
        if not self.is_ready:
            return []

        def _query():
            return self._client.table("session_messages") \
                .select("sender_role, message_text") \
                .eq("session_id", session_id) \
                .order("created_at", desc=True) \
                .limit(limit) \
                .execute()

        try:
            response = await asyncio.to_thread(_query)
            # Reverse to get chronological order [oldest -> newest]
            return response.data[::-1] if response and response.data else []
        except Exception as e:
            logger.error(f"DB Error (get_history): {e}")
            return []

    async def add_message(self, session_id: str, role: str, text: str):
        """Save a new message and increment turn count if AI replied asynchronously."""
        if not self.is_ready:
            return

        def _insert_msg():
            msg_data = {
                "session_id": session_id,
                "sender_role": role,
                "message_text": text
            }
            return self._client.table("session_messages").insert(msg_data).execute()

        try:
            # 1. Insert message in background thread
            await asyncio.to_thread(_insert_msg)

            # 2. Increment turn count if AI replied
            if role == "honeypot":
                session = await self.get_session(session_id)
                if session:
                    new_count = session.get("turns_completed", 0) + 1
                    def _update_turns():
                        return self._client.table("scam_sessions") \
                            .update({"turns_completed": new_count}) \
                            .eq("id", session_id) \
                            .execute()
                    await asyncio.to_thread(_update_turns)

        except Exception as e:
            logger.error(f"DB Error (add_message): {e}")

    async def terminate_session(self, session_id: str, reason: str):
        """Close a session asynchronously."""
        if not self.is_ready:
            return

        def _update():
            return self._client.table("scam_sessions") \
                .update({"status": reason}) \
                .eq("id", session_id) \
                .execute()

        try:
            await asyncio.to_thread(_update)
        except Exception as e:
            logger.error(f"DB Error (terminate_session): {e}")

def get_db() -> DatabaseManager:
    """Get singleton DatabaseManager instance."""
    return DatabaseManager()
