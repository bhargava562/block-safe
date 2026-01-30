"""
BlockSafe Main Application
FastAPI application with lifespan management
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette import status

from app.config import get_settings
from app.api.v1.routes import router as api_router, health_router
from app.utils.logger import logger


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan handler.
    Initializes models and services at startup, cleans up at shutdown.
    """
    logger.info("BlockSafe API starting up...")

    # Load settings (validates environment)
    try:
        settings = get_settings()
        logger.info("Configuration loaded successfully")
    except Exception as e:
        logger.error(f"Configuration error: {e}")
        raise

    # Pre-load Whisper model (optional, can be lazy-loaded on first audio request)
    try:
        from app.intelligence.speech_to_text import WhisperTranscriber
        if WhisperTranscriber.is_loaded():
            logger.info("Whisper model already loaded")
        else:
            logger.info("Whisper model will be lazy-loaded on first audio request")
    except Exception as e:
        logger.warning(f"Whisper preload skipped: {e}")

    # Initialize Gemini-based services
    try:
        from app.core.scam_detector import get_classifier
        get_classifier()
        logger.info("Scam classifier initialized")
    except Exception as e:
        logger.error(f"Classifier initialization failed: {e}")
        raise

    logger.info("BlockSafe API ready to accept requests")

    yield  # Application runs here

    # Shutdown
    logger.info("BlockSafe API shutting down...")


# Create FastAPI application
app = FastAPI(
    title="BlockSafe API",
    description="""
    **BlockSafe** - Agentic Scam Detection & Intelligence Extraction API
    
    ## Features
    
    - 🔍 **Multi-modal Analysis**: Text and audio (voice call) scam detection
    - 🎯 **Scam Classification**: LLM-powered classification with confidence scores
    - 🔬 **Strategy Fingerprinting (SSF)**: Behavioral pattern analysis for ecosystem learning
    - 🍯 **Agentic Honeypot**: Autonomous intelligence extraction with kill-switch logic
    - 🛡️ **Dual Modes**: Shield (protection) and Honeypot (extraction) modes
    
    ## Authentication
    
    All analysis endpoints require API key authentication via `X-API-KEY` header.
    
    ## Endpoints
    
    - `POST /api/v1/analyze/text` - Analyze text messages
    - `POST /api/v1/analyze/audio` - Analyze audio files
    - `GET /health` - Health check (no auth required)
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS middleware (configure as needed for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    logger.warning(f"HTTPException: {exc.detail} | path={request.url.path}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "type": "http_exception"
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    logger.warning(f"Validation error: {exc.errors()} | path={request.url.path}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": exc.errors(),
            "type": "validation_error"
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle uncaught exceptions gracefully"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "type": type(exc).__name__
        }
    )


# Include routers
app.include_router(api_router)
app.include_router(health_router)


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information"""
    return {
        "name": "BlockSafe API",
        "version": "1.0.0",
        "description": "Agentic Scam Detection & Intelligence Extraction",
        "docs": "/docs",
        "health": "/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
