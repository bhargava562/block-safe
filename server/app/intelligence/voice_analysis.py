"""
BlockSafe Voice Analysis Module
Audio feature extraction for cross-modal intelligence
"""

import tempfile
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List
from dataclasses import dataclass

from app.utils.logger import logger


@dataclass
class VoiceSignals:
    """Voice-based signals for SSF integration"""
    speech_rate: float  # Words per minute (estimated)
    urgency_indicators: List[str]
    repetition_detected: bool
    duration_seconds: float
    silence_ratio: float


class VoiceAnalyzer:
    """
    Analyzes audio features to detect urgency and patterns.
    Feeds into Scam Strategy Fingerprint (SSF).
    """

    _executor = ThreadPoolExecutor(max_workers=2)

    def _analyze_sync(self, audio_path: str, transcript: str) -> VoiceSignals:
        """
        Synchronous audio analysis using librosa.

        Args:
            audio_path: Path to audio file
            transcript: Transcribed text for word count

        Returns:
            VoiceSignals dataclass
        """
        try:
            import librosa
            import numpy as np

            # Load audio
            y, sr = librosa.load(audio_path, sr=None)
            duration = librosa.get_duration(y=y, sr=sr)

            # Calculate speech rate (words per minute)
            word_count = len(transcript.split()) if transcript else 0
            speech_rate = (word_count / duration * 60) if duration > 0 else 0

            # Detect silence ratio using RMS energy
            rms = librosa.feature.rms(y=y)[0]
            silence_threshold = np.percentile(rms, 10)
            silence_frames = np.sum(rms < silence_threshold)
            silence_ratio = silence_frames / len(rms) if len(rms) > 0 else 0

            # Urgency indicators based on speech characteristics
            urgency_indicators = []

            # Fast speech (> 160 WPM is considered fast)
            if speech_rate > 160:
                urgency_indicators.append("fast_speech")

            # Very fast speech (> 200 WPM)
            if speech_rate > 200:
                urgency_indicators.append("very_fast_speech")

            # Low silence ratio (rapid, continuous speech)
            if silence_ratio < 0.15:
                urgency_indicators.append("continuous_speech")

            # Detect repetition in transcript
            repetition_detected = self._detect_repetition(transcript)
            if repetition_detected:
                urgency_indicators.append("repetitive_phrases")

            return VoiceSignals(
                speech_rate=round(speech_rate, 2),
                urgency_indicators=urgency_indicators,
                repetition_detected=repetition_detected,
                duration_seconds=round(duration, 2),
                silence_ratio=round(silence_ratio, 3)
            )

        except Exception as e:
            logger.error(f"Voice analysis failed: {e}")
            # Return default values on failure
            return VoiceSignals(
                speech_rate=0.0,
                urgency_indicators=[],
                repetition_detected=False,
                duration_seconds=0.0,
                silence_ratio=0.0
            )

    def _detect_repetition(self, text: str, threshold: int = 2) -> bool:
        """
        Detect if phrases are repeated multiple times.

        Args:
            text: Transcript text
            threshold: Minimum repetitions to trigger

        Returns:
            True if repetition detected
        """
        if not text:
            return False

        words = text.lower().split()
        if len(words) < 6:
            return False

        # Check for repeated 3-grams
        trigrams = [' '.join(words[i:i+3]) for i in range(len(words) - 2)]
        trigram_counts = {}
        for tg in trigrams:
            trigram_counts[tg] = trigram_counts.get(tg, 0) + 1

        # If any trigram appears more than threshold times
        for count in trigram_counts.values():
            if count >= threshold:
                return True

        return False

    async def analyze(self, audio_bytes: bytes, transcript: str) -> VoiceSignals:
        """
        Async audio analysis.

        Args:
            audio_bytes: Raw audio file bytes
            transcript: Transcribed text

        Returns:
            VoiceSignals dataclass
        """
        # Write to temporary file
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp_file:
            tmp_file.write(audio_bytes)
            tmp_path = tmp_file.name

        try:
            loop = asyncio.get_event_loop()
            signals = await loop.run_in_executor(
                self._executor,
                self._analyze_sync,
                tmp_path,
                transcript
            )
            return signals
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


# Module-level instance
_voice_analyzer: Optional[VoiceAnalyzer] = None


def get_voice_analyzer() -> VoiceAnalyzer:
    """Get VoiceAnalyzer instance"""
    global _voice_analyzer
    if _voice_analyzer is None:
        _voice_analyzer = VoiceAnalyzer()
    return _voice_analyzer
