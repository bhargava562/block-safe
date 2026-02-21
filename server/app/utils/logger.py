"""
BlockSafe Logger Utility
Structured logging configuration driven by config.LOG_LEVEL
"""

import logging
import sys
from typing import Optional


def setup_logger(
    name: str = "blocksafe",
    level: Optional[int] = None,
    log_format: Optional[str] = None
) -> logging.Logger:
    """
    Configure and return a structured logger.

    Args:
        name: Logger name
        level: Logging level (auto-detected from config if None)
        log_format: Custom format string

    Returns:
        Configured logger instance
    """
    # Auto-detect level from config if not explicitly provided
    if level is None:
        try:
            from app.config import get_settings
            level = getattr(logging, get_settings().LOG_LEVEL, logging.INFO)
        except Exception:
            level = logging.INFO  # safe fallback during startup

    if log_format is None:
        log_format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

    log = logging.getLogger(name)
    log.setLevel(level)

    # Clear existing handlers to prevent duplication/misconfiguration
    if log.hasHandlers():
        log.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    formatter = logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S")
    handler.setFormatter(formatter)
    log.addHandler(handler)

    return log


# Default application logger
logger = setup_logger()


def log_request(request_id: str, endpoint: str, mode: str) -> None:
    """Log incoming request"""
    logger.info(f"Request {request_id} | Endpoint: {endpoint} | Mode: {mode}")


def log_classification(request_id: str, is_scam: bool, confidence: float, scam_type: Optional[str]) -> None:
    """Log classification result"""
    logger.info(
        f"Classification {request_id} | is_scam: {is_scam} | "
        f"confidence: {confidence:.2f} | type: {scam_type or 'N/A'}"
    )


def log_honeypot(request_id: str, turns: int, reason: str) -> None:
    """Log honeypot engagement"""
    logger.info(f"Honeypot {request_id} | Turns: {turns} | Termination: {reason}")


def log_error(request_id: str, error: str) -> None:
    """Log error"""
    logger.error(f"Error {request_id} | {error}")
