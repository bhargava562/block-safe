"""
BlockSafe Custom Errors
HTTP exceptions and error responses
"""

from fastapi import HTTPException, status


class AudioFileTooLargeError(HTTPException):
    """Raised when uploaded audio file exceeds MAX_AUDIO_MB limit"""

    def __init__(self, max_mb: int, actual_mb: float):
        super().__init__(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Audio file too large. Maximum allowed: {max_mb}MB, received: {actual_mb:.2f}MB"
        )


class InvalidAudioFormatError(HTTPException):
    """Raised when audio file format is not supported"""

    def __init__(self, filename: str):
        super().__init__(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Unsupported audio format for file: {filename}. Supported formats: wav, mp3, m4a, ogg, flac"
        )


class TranscriptionError(HTTPException):
    """Raised when speech-to-text fails"""

    def __init__(self, detail: str = "Failed to transcribe audio"):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail
        )


class ClassificationError(HTTPException):
    """Raised when scam classification fails"""

    def __init__(self, detail: str = "Failed to classify message"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )


class HoneypotError(HTTPException):
    """Raised when honeypot engagement fails"""

    def __init__(self, detail: str = "Honeypot engagement failed"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )


class EmptyMessageError(HTTPException):
    """Raised when message content is empty"""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message content cannot be empty"
        )
