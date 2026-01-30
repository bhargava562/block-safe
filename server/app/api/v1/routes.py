"""
BlockSafe API Routes
Main API endpoints for scam analysis
"""

from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, UploadFile, status
from fastapi.responses import JSONResponse

from app.config import get_settings, Settings
from app.security.rate_limit import enforce_rate_limit
from app.api.v1.schemas import (
    TextInput,
    AnalysisResponse,
    HealthResponse
)
from app.api.v1.errors import (
    AudioFileTooLargeError,
    InvalidAudioFormatError,
    TranscriptionError,
    EmptyMessageError
)
from app.core.scam_detector import get_classifier
from app.core.ssf_engine import get_ssf_engine
from app.core.honeypot import get_honeypot_agent
from app.core.response_builder import ResponseBuilder
from app.intelligence.speech_to_text import get_transcriber
from app.intelligence.voice_analysis import get_voice_analyzer
from app.utils.helpers import sanitize_text
from app.utils.logger import logger, log_request, log_classification


# Create router
router = APIRouter(prefix="/api/v1", tags=["Analysis"])

# Supported audio formats
SUPPORTED_AUDIO_FORMATS = {".wav", ".mp3", ".m4a", ".ogg", ".flac", ".webm"}


@router.post(
    "/analyze/text",
    response_model=AnalysisResponse,
    summary="Analyze text for scam detection",
    description="Analyze a text message for scam indicators with optional honeypot engagement"
)
async def analyze_text(
    input_data: TextInput,
    settings: Annotated[Settings, Depends(get_settings)],
    rate_limit: None = Depends(enforce_rate_limit)
) -> AnalysisResponse:
    """
    Analyze text message for scam detection.

    - **message**: The text message to analyze
    - **mode**: "shield" (default) for protection only, "honeypot" for active extraction
    """
    request_id = str(uuid4())
    log_request(request_id, "/analyze/text", input_data.mode)

    # Sanitize input
    message = sanitize_text(input_data.message)
    if not message.strip():
        raise EmptyMessageError()

    # Get service instances
    classifier = get_classifier()
    ssf_engine = get_ssf_engine()
    honeypot_agent = get_honeypot_agent()

    # Step 1: Classify the message
    classification = await classifier.classify(message)
    log_classification(
        request_id,
        classification.is_scam,
        classification.confidence,
        classification.scam_type
    )

    # Step 2: Generate SSF profile
    ssf_result = ssf_engine.analyze(message)

    # Step 3: Honeypot engagement (if applicable)
    honeypot_result = None
    if (
        classification.is_scam and
        classification.confidence >= settings.HONEYPOT_CONFIDENCE_THRESHOLD
    ):
        honeypot_result = await honeypot_agent.engage(
            initial_message=message,
            mode=input_data.mode,
            initial_entities=classification.extracted_entities,
            request_id=request_id
        )

    # Step 4: Build response
    response = ResponseBuilder.build(
        classification=classification,
        ssf=ssf_result,
        honeypot_result=honeypot_result,
        original_message=message,
        mode=input_data.mode,
        request_id=request_id
    )

    return response


@router.post(
    "/analyze/audio",
    response_model=AnalysisResponse,
    summary="Analyze audio for scam detection",
    description="Analyze an audio file (call recording) for scam indicators"
)
async def analyze_audio(
    settings: Annotated[Settings, Depends(get_settings)],
    rate_limit: None = Depends(enforce_rate_limit),
    file: UploadFile = File(..., description="Audio file to analyze"),
    mode: Literal["shield", "honeypot"] = Form(
        default="shield",
        description="Operation mode"
    )
) -> AnalysisResponse:
    """
    Analyze audio file for scam detection.

    - **file**: Audio file (wav, mp3, m4a, ogg, flac)
    - **mode**: "shield" (default) for protection only, "honeypot" for active extraction
    """
    request_id = str(uuid4())
    log_request(request_id, "/analyze/audio", mode)

    # Validate file format
    filename = file.filename or "unknown"
    file_ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if file_ext not in SUPPORTED_AUDIO_FORMATS:
        raise InvalidAudioFormatError(filename)

    # Read file and check size
    audio_bytes = await file.read()
    file_size_mb = len(audio_bytes) / (1024 * 1024)

    if file_size_mb > settings.MAX_AUDIO_MB:
        raise AudioFileTooLargeError(settings.MAX_AUDIO_MB, file_size_mb)

    # Get service instances
    transcriber = get_transcriber()
    voice_analyzer = get_voice_analyzer()
    classifier = get_classifier()
    ssf_engine = get_ssf_engine()
    honeypot_agent = get_honeypot_agent()

    # Step 1: Transcribe audio
    try:
        transcript, audio_metadata = await transcriber.transcribe(audio_bytes)
    except Exception as e:
        logger.error(f"Transcription failed: {e}")
        raise TranscriptionError(f"Failed to transcribe audio: {str(e)}")

    if not transcript.strip():
        raise TranscriptionError("No speech detected in audio file")

    # Step 2: Analyze voice signals
    voice_signals = await voice_analyzer.analyze(audio_bytes, transcript)

    # Step 3: Classify the transcript
    classification = await classifier.classify(transcript)
    log_classification(
        request_id,
        classification.is_scam,
        classification.confidence,
        classification.scam_type
    )

    # Step 4: Generate SSF profile (with voice signals)
    ssf_result = ssf_engine.analyze(transcript, voice_signals)

    # Step 5: Honeypot engagement (if applicable)
    honeypot_result = None
    if (
        classification.is_scam and
        classification.confidence >= settings.HONEYPOT_CONFIDENCE_THRESHOLD
    ):
        honeypot_result = await honeypot_agent.engage(
            initial_message=transcript,
            mode=mode,
            initial_entities=classification.extracted_entities,
            request_id=request_id
        )

    # Step 6: Build response
    response = ResponseBuilder.build(
        classification=classification,
        ssf=ssf_result,
        honeypot_result=honeypot_result,
        original_message=transcript,
        mode=mode,
        transcript=transcript,
        voice_signals=voice_signals,
        request_id=request_id
    )

    return response


# Health check endpoint (no auth required)
health_router = APIRouter(tags=["Health"])


@health_router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check API health status"
)
async def health_check() -> HealthResponse:
    """Health check endpoint for connectivity verification"""
    from datetime import datetime, timezone

    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat()
    )
