# ============================================================
# BlockSafe Dockerfile — Multi-Stage Production Build
# Image: bhargava93099/blocksafe:latest
# ============================================================

# ── Stage 1: Builder ─────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies for native extensions (numpy, librosa)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libsndfile1-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements-docker.txt /build/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r /build/requirements.txt


# ── Stage 2: Runtime ─────────────────────────────────────────
FROM python:3.11-slim AS runtime

# OCI labels
LABEL org.opencontainers.image.title="BlockSafe API" \
      org.opencontainers.image.description="Agentic Scam Detection & Intelligence Extraction" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="bhargava93099" \
      org.opencontainers.image.source="https://github.com/bhargava562/block-safe"

# Runtime-only native lib required by soundfile / librosa
RUN apt-get update && \
    apt-get install -y --no-install-recommends libsndfile1 curl && \
    rm -rf /var/lib/apt/lists/*

# Prevent Python from writing .pyc and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy pre-built Python packages from builder stage
COPY --from=builder /install /usr/local

# Copy application code
COPY server /app

# Create non-root user for security
RUN useradd -m -u 1000 blocksafe && chown -R blocksafe:blocksafe /app
USER blocksafe

EXPOSE 8000

# Health check (uses curl installed above)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]