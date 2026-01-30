"""
BlockSafe Logger Utility
Structured logging configuration
"""

import logging
import sys
from typing import Optional


def setup_logger(
    name: str = "blocksafe",
    level: int = logging.INFO,
    log_format: Optional[str] = None
) -> logging.Logger:
    """
    Configure and return a structured logger.

    Args:
        name: Logger name
        level: Logging level
        log_format: Custom format string

    Returns:
        Configured logger instance
    """
    if log_format is None:
        log_format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        formatter = logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


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
