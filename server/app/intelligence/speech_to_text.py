"""
BlockSafe Speech-to-Text Module
Whisper-based audio transcription with singleton model loading
"""

import io
import tempfile
import os
from typing import Optional, Tuple
import asyncio
from concurrent.futures import ThreadPoolExecutor

from app.config import get_settings
from app.utils.logger import logger


class WhisperTranscriber:
    """
    Whisper-based speech-to-text transcriber.
    Uses singleton pattern to load model once at startup.
    """

    _instance: Optional["WhisperTranscriber"] = None
    _model = None
    _executor = ThreadPoolExecutor(max_workers=2)

    def __new__(cls) -> "WhisperTranscriber":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        # Only initialize once
        if WhisperTranscriber._model is None:
            self._load_model()

    def _load_model(self) -> None:
        """Load the Whisper model (called once at startup)"""
        try:
            from faster_whisper import WhisperModel

            settings = get_settings()
            logger.info(f"Loading Whisper model: {settings.WHISPER_MODEL_SIZE}")

            WhisperTranscriber._model = WhisperModel(
                settings.WHISPER_MODEL_SIZE,
                device=settings.WHISPER_DEVICE,
                compute_type=settings.WHISPER_COMPUTE_TYPE
            )

            logger.info("Whisper model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load Whisper model: {e}")
            raise RuntimeError(f"Whisper initialization failed: {e}")

    def _transcribe_sync(self, audio_path: str) -> Tuple[str, dict]:
        """
        Synchronous transcription (runs in thread pool).

        Returns:
            Tuple of (transcript, metadata)
        """
        if self._model is None:
            raise RuntimeError("Whisper model not initialized")

        segments, info = self._model.transcribe(
            audio_path,
            beam_size=5,
            language="en",  # Can be made configurable
            vad_filter=True,  # Voice activity detection
            vad_parameters=dict(
                min_silence_duration_ms=500
            )
        )

        # Collect all segments
        transcript_parts = []
        for segment in segments:
            transcript_parts.append(segment.text.strip())

        transcript = " ".join(transcript_parts)

        metadata = {
            "language": info.language,
            "language_probability": info.language_probability,
            "duration": info.duration
        }

        return transcript, metadata

    async def transcribe(self, audio_bytes: bytes) -> Tuple[str, dict]:
        """
        Async transcription from audio bytes.

        Args:
            audio_bytes: Raw audio file bytes

        Returns:
            Tuple of (transcript, metadata)
        """
        # Write to temporary file (faster-whisper needs file path)
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp_file:
            tmp_file.write(audio_bytes)
            tmp_path = tmp_file.name

        try:
            # Run transcription in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            transcript, metadata = await loop.run_in_executor(
                self._executor,
                self._transcribe_sync,
                tmp_path
            )
            return transcript, metadata
        finally:
            # Clean up temp file
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    @classmethod
    def is_loaded(cls) -> bool:
        """Check if model is loaded"""
        return cls._model is not None

    @classmethod
    def preload(cls) -> None:
        """Preload the model (call at startup)"""
        instance = cls()
        logger.info("Whisper model preloaded and ready")


# Singleton instance getter
def get_transcriber() -> WhisperTranscriber:
    """Get the singleton WhisperTranscriber instance"""
    return WhisperTranscriber()
