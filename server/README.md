# BlockSafe API Server

**Agentic Scam Detection & Intelligence Extraction Backend**

---

## Contents
- [Overview](#overview)
- [Key Capabilities](#key-capabilities)
- [Architecture](#architecture)
- [Data Flow](#data-flow)
- [Configuration](#configuration)
- [Security & Compliance](#security--compliance)
- [Performance Features](#performance-features)
- [API Reference](#api-reference)
- [Core Modules](#core-modules)
- [Testing](#testing)
- [Deployment Notes](#deployment-notes)
- [Project Structure](#project-structure)

---

## Overview
BlockSafe is a production-grade FastAPI backend that ingests text or audio, detects scams, fingerprints scam strategies (SSF), and optionally engages scammers via a controlled honeypot to extract intelligence. The system is stateless, returns deterministic JSON, and is built for automated evaluation.

---

## Key Capabilities
- **Multi-modal analysis**: Text + audio (Whisper-based transcription) → unified classification.
- **Gemini-powered reasoning**: Uses `google-genai` with configurable model (default `gemini-2.0-flash`).
- **Scam Strategy Fingerprinting (SSF)**: Detects urgency, authority impersonation, payment escalation, and channel switching.
- **Dual modes**: `shield` (safe deflection, default) and `honeypot` (agentic engagement).
- **Honeypot kill-switches**: Max turns, no-progress turns, repeated pattern detection, and extraction threshold.
- **Deterministic JSON**: Strict Pydantic schemas for evaluation safety.

---

## Architecture
```
Client ──► FastAPI (auth + rate limit + validation)
             │
             ├─ /api/v1/analyze/text
             ├─ /api/v1/analyze/audio
             └─ /health
             │
             ▼
    ┌───────────────────────────┐
    │  Input Normalization      │
    │  - sanitize_text          │
    │  - file size/format check │
    └───────────┬──────────────┘
                ▼
    ┌───────────────────────────┐
    │  Speech-to-Text (audio)   │
    │  - faster-whisper         │
    │  - voice signals          │
    └───────────┬──────────────┘
                ▼
    ┌───────────────────────────┐
    │  Scam Classifier (LLM)    │
    │  - Gemini 2.0 Flash       │
    │  - TTL cache (5m)         │
    └───────────┬──────────────┘
                ▼
    ┌───────────────────────────┐
    │  SSF Engine               │
    │  - urgency/authority      │
    │  - payment/ch switching   │
    │  - voice urgency signals  │
    └───────────┬──────────────┘
                ▼
    ┌───────────────────────────┐
    │  Honeypot (optional)      │
    │  - bounded turns          │
    │  - kill-switches          │
    └───────────┬──────────────┘
                ▼
    ┌───────────────────────────┐
    │  Response Builder         │
    │  - evidence level         │
    │  - deterministic JSON     │
    └───────────────────────────┘
```

---

## Data Flow
1) **Auth & rate limit**: `X-API-KEY` checked; `enforce_rate_limit` throttles per key/IP.
2) **Validation**: Pydantic request models; FastAPI validation errors return 422 via global handler.
3) **Audio path**: size/format guard → Whisper transcription → voice signal analysis.
4) **Classification**: Gemini prompt → JSON parsed → entities extracted via regex helpers.
5) **SSF**: Urgency/authority/payment/channel signals + optional voice urgency.
6) **Honeypot** (if mode=`honeypot` and confidence ≥ threshold): bounded turns, kill-switches, safe summary.
7) **Response**: Built via `ResponseBuilder`, includes evidence level and SSF profile.

---

## Configuration
All secrets and environment-specific values are injected via environment variables. **Do not hardcode keys or base URLs in code.**

| Var | Required | Default | Description |
| --- | --- | --- | --- |
| `GEMINI_API_KEY` | ✅ | - | Gemini API key (env only) |
| `API_AUTH_KEY` | ✅ | - | API key for client auth |
| `MAX_AUDIO_MB` | ❌ | 10 | Max upload size (MB) |
| `GEMINI_MODEL` | ❌ | gemini-2.0-flash | Gemini model name |
| `HONEYPOT_MAX_TURNS` | ❌ | 5 | Honeypot max turns |
| `HONEYPOT_CONFIDENCE_THRESHOLD` | ❌ | 0.85 | Confidence to trigger honeypot |
| `HONEYPOT_NO_PROGRESS_TURNS` | ❌ | 2 | Kill-switch: no new entities over N turns |
| `WHISPER_MODEL_SIZE` | ❌ | base | Whisper size |
| `WHISPER_DEVICE` | ❌ | cpu | Device |
| `WHISPER_COMPUTE_TYPE` | ❌ | int8 | Compute precision |

### Environment files
- Use `.env` locally (gitignored). Production/staging should set env vars at the platform level.
- Example: `.env.example` (kept) — never commit populated `.env`.

---

## Security & Compliance
- **Secrets management**: `SecretStr` in Pydantic; `.gitignore` blocks `.env*`, secrets folders, local configs.
- **Auth**: API key via `X-API-KEY` with constant-time comparison.
- **Rate limiting**: In-memory limiter (`enforce_rate_limit`); per API key/IP, returns 429 with `Retry-After`.
- **Validation**: Pydantic schemas + global `RequestValidationError` handler (422 JSON body).
- **Global exception handling**: Specific handlers for `HTTPException`, `RequestValidationError`, and catch-all 500 with safe JSON payloads.
- **Input sanitization**: Control-char stripping, length limiting in `sanitize_text`; file size/format guards on audio.
- **Kill-switches**: Honeypot bounded turns, no-progress turns, repeated pattern aborts.
- **Determinism**: Response builder rounds confidences, clamps evidence levels, and enforces schema.

---

## Performance Features
- **Classifier TTL cache**: 5-minute, max 100-entry in-memory cache to avoid duplicate Gemini calls.
- **Lazy model loading**: Whisper is lazy-loaded; Gemini client initialized once.
- **Rate limiting**: Prevents abuse and reduces load.

---

## API Reference
### Auth
All analysis endpoints require `X-API-KEY`.

### Endpoints
- `POST /api/v1/analyze/text`
- `POST /api/v1/analyze/audio`
- `GET /health` (no auth)

### Request Examples
**Text**
```json
{
  "message": "Your account is blocked, click here...",
  "mode": "shield"
}
```

**Audio (multipart)**
- `file`: audio (.wav/.mp3/.m4a/.ogg/.flac/.webm)
- `mode`: `shield` | `honeypot` (default `shield`)

### Response (shape)
```json
{
  "request_id": "uuid",
  "timestamp": "ISO-8601",
  "is_scam": true,
  "confidence": 0.96,
  "scam_type": "bank_impersonation",
  "transcript": "...",                // audio only
  "original_message": "...",          // text or transcript
  "extracted_entities": {
    "upi_ids": [],
    "bank_accounts": [],
    "urls": [],
    "phone_numbers": []
  },
  "ssf_profile": {
    "urgency_score": 0.8,
    "authority_claims": ["Bank"],
    "payment_escalation": true,
    "channel_switch_intent": "WhatsApp",
    "urgency_phrases": ["immediately"],
    "strategy_summary": "High-pressure urgency tactics detected. Impersonates: Bank. Contains payment/financial demands."
  },
  "voice_analysis": null,
  "honeypot_result": null,
  "agent_summary": "...",
  "evidence_level": "HIGH",
  "operation_mode": "shield"
}
```

### Error Codes
- 400 Empty/invalid payload
- 401/403 Auth failures
- 413 Audio too large (MAX_AUDIO_MB)
- 415 Unsupported media type
- 422 Validation/transcription errors
- 429 Rate limit exceeded
- 500 Unhandled errors (structured JSON)

---

## Core Modules
- `app/main.py`: App factory, CORS, lifespan, global exception handlers.
- `app/api/v1/routes.py`: Text/audio endpoints, size/format guards, rate limiting.
- `app/api/v1/schemas.py`: Strict Pydantic models for requests/responses.
- `app/core/scam_detector.py`: Gemini classifier + TTL cache.
- `app/core/ssf_engine.py`: Scam Strategy Fingerprinting (urgency/authority/payment/channel + voice).
- `app/core/honeypot.py`: Bounded honeypot with kill-switch logic and shield mode.
- `app/core/response_builder.py`: Deterministic JSON assembly, evidence level.
- `app/intelligence/speech_to_text.py`: Whisper transcription (lazy load).
- `app/intelligence/voice_analysis.py`: Speech-rate and urgency indicators.
- `app/utils/helpers.py`: Entity extraction (UPI, bank accounts, URLs, phones) and sanitization.
- `app/security/auth.py`: API key verification.
- `app/security/rate_limit.py`: In-memory rate limiting + dependency.

---

## Testing
- Suites: `test_api.py`, `test_ssf.py`, `test_helpers.py`
- Total: **91 tests** (unit-style; mocks Gemini where needed)

Run all tests:
```bash
cd server
.\.venv\Scripts\python.exe -m pytest app/tests -v --tb=short
```

---

## Deployment Notes
- **Secrets**: Provide via environment (e.g., platform secret store). Never bake keys into images or code.
- **Base URLs**: Configure externally (ingress / gateway). No hardcoded public endpoints in code.
- **CORS**: Restrict `allow_origins` for production.
- **Rate limiting**: Current in-memory limiter; for production use Redis/managed store.
- **Logging**: `app/utils/logger.py` controls format/levels; route logs include request IDs.
- **Scaling**: Stateless; horizontal scaling works with shared cache/limiter (backed store recommended).

---

## Project Structure
```
server/
├── app/
│   ├── api/v1/
│   ├── core/
│   ├── intelligence/
│   ├── security/
│   ├── utils/
│   ├── tests/
│   ├── config.py
│   ├── main.py
│   └── dependencies.py
├── requirements.txt
├── pytest.ini
├── run.py
├── .gitignore
└── README.md
```
