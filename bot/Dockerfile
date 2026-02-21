# ============================================================
# BlockSafe Telegram Bot — Production Build
# ============================================================

FROM python:3.11-slim

WORKDIR /app

# Prevent Python from writing .pyc and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY bot/requirements-frontend.txt .
RUN pip install --no-cache-dir -r requirements-frontend.txt

COPY bot /app

# Non-root user
RUN useradd -m -u 1000 blocksafe-bot && chown -R blocksafe-bot:blocksafe-bot /app
USER blocksafe-bot

CMD ["python", "main.py"]
