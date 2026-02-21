# BlockSafe - AI-Powered Scam Detection System

[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://docker.com)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-green)](https://fastapi.tiangolo.com)
[![Gemini](https://img.shields.io/badge/Gemini-2.5%20Flash-orange)](https://ai.google.dev)
[![LangChain](https://img.shields.io/badge/LangChain-Multi--Agent-purple)](https://python.langchain.com/)

> **Live API Endpoint**: `https://blocksafe-latest.onrender.com/api/v1/analyze/text`

BlockSafe is a production-ready AI system for real-time scam detection and intelligence extraction. It provides both defensive (Shield) and intelligence gathering (Honeypot) capabilities with multi-modal analysis supporting text and audio inputs.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+ or Docker installed
- Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey)
- (Optional) OpenAI API key, Groq API key for multi-agent mode

### 1. Clone Repository
```bash
git clone <repository-url>
cd BlockSafe
```

### 2. Environment Setup
```bash
cp server/.env.example server/.env
# Edit server/.env with your API keys
```

### 3. Run with Docker
```bash
docker build -t blocksafe:latest -f Dockerfile .
docker run -d -p 8000:8000 \
  -e GEMINI_API_KEY=your-gemini-key \
  -e API_AUTH_KEY=your-secure-api-key \
  --name blocksafe-container \
  blocksafe:latest
```

### 4. Test API
```bash
curl http://localhost:8000/health
```

---

## 🏗️ Multi-Agent Architecture

BlockSafe uses a **two-tier multi-agent intelligence layer** powered by LangChain:

### Tier 1: Classification Pipeline (`agents.py`)
Called first by `scam_detector.classify()` for every incoming message:

```
                        ┌─────────────────────────┐
                        │      run_agents()       │
                        │   asyncio.gather()      │
                        └─────────┬───────────────┘
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
          ┌─────────────────┐         ┌─────────────────┐
          │  Profiler Agent │         │ Fact-Checker     │
          │  ─────────────  │         │  ─────────────   │
          │ OpenAI gpt-4o   │         │ Gemini Flash     │
          │  ↓ fallback     │         │  ↓ fallback      │
          │ Groq Llama-3.3  │         │ Groq Llama-3.3   │
          │  ↓ fallback     │         │                   │
          │ Heuristic rules │         │                   │
          └────────┬────────┘         └────────┬──────────┘
                   │                           │
                   └─────────┬─────────────────┘
                             ▼
                   ┌─────────────────────┐
                   │   AgentAnalysis     │
                   │  ───────────────    │
                   │ • fear_score        │
                   │ • urgency_score     │
                   │ • authority_score   │
                   │ • cognitive_risk    │
                   │ • policy_violation  │
                   │ • provider_used     │
                   └─────────────────────┘
```

| Agent | Primary Provider | Fallback | Purpose |
|-------|-----------------|----------|---------|
| **Profiler** | OpenAI `gpt-4o-mini` | Groq `llama-3.3-70b` → Heuristic | Detect urgency, fear induction, authority impersonation |
| **Fact-Checker** | Gemini Flash | Groq `llama-3.3-70b` | Extract entities, verify claims against real policies |

### Tier 2: Deep Analysis Swarm (`agent_swarm.py`)
Called after classification for additional intelligence:

- **CognitiveProfiler** — Emotional manipulation analysis
- **PolicyValidator** — Real-world policy violation verification
- **ArtifactExtractor** — IoC extraction (regex, no LLM)
- **CampaignCluster** — Merging Intervals engine for threat campaign tracking
- **DecisionSynthesis** — Final score aggregation

### Quota Fallback & High Availability

All LLM calls implement automatic failover:

```
Primary Provider (OpenAI / Gemini)
    → Rate limit or error
        → Groq Llama-3.3-70b (fallback)
            → Heuristic rules (safety net)
```

The `provider_used` field in the API response tracks which path was taken (e.g., `openai+gemini`, `groq_fallback+groq_fallback`).

---

## 📡 API Documentation

### Base URL
```
http://localhost:8000
```

### Authentication
All API endpoints (except `/health`) require authentication via `X-API-KEY` header.

### Endpoints

#### Health Check
```bash
curl -X GET http://localhost:8000/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-02-21T11:30:00Z"
}
```

#### Text Analysis
```bash
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: YOUR_API_KEY" \
  -d '{
    "message": "SBI Bank Alert: Your account is restricted due to pending KYC. Update PAN immediately via sbi-kyc-update.info or your account will be blocked in 15 mins.",
    "mode": "shield"
  }'
```

**Request Body:**
```json
{
  "message": "string (1-10000 chars, required)",
  "mode": "shield | honeypot (default: shield)",
  "session_id": "string (optional, auto-generated if not provided)"
}
```

**Response:**
```json
{
  "request_id": "uuid",
  "session_id": "uuid",
  "timestamp": "2026-02-21T11:30:06Z",
  "is_scam": true,
  "confidence": 0.95,
  "scam_type": "bank_impersonation",
  "transcript": null,
  "original_message": "SBI Bank Alert: Your account is restricted...",
  "extracted_entities": {
    "upi_ids": [],
    "bank_accounts": [],
    "urls": [],
    "phone_numbers": []
  },
  "ssf_profile": {
    "urgency_score": 0.9,
    "authority_claims": ["Bank"],
    "payment_escalation": false,
    "channel_switch_intent": null,
    "urgency_phrases": ["immediately", "account will be blocked"],
    "strategy_summary": "Impersonates: Bank. High cognitive risk (0.8) with known policy violation.",
    "fear_score": 0.8,
    "authority_score": 0.7,
    "cognitive_risk_score": 0.8,
    "policy_violation": {
      "entity": "SBI Bank",
      "claimed_action": "Update PAN immediately via sbi-kyc-update.info",
      "verified_result": "SBI Bank does not send alerts with specific timeframes for account blocking, nor does it ask customers to update KYC via unofficial websites.",
      "source_url": null
    }
  },
  "voice_analysis": null,
  "honeypot_result": null,
  "agent_summary": "High-confidence bank impersonation detected.",
  "evidence_level": "HIGH",
  "operation_mode": "shield",
  "provider_used": "openai+gemini",
  "ai_feedback": {
    "openai_emotional_profile": "The message uses fear induction by threatening account blockage...",
    "gemini_policy_violations": "SBI Bank does not ask customers to update KYC via unofficial websites...",
    "primary_suspected_reason": "Violates SBI Bank's official communication policy."
  },
  "campaign_info": {
    "campaign_id": "CAMP-SBI-BANKIMPER-005",
    "is_new_campaign": false,
    "total_attempts_tracked": 2,
    "primary_target_entity": "SBI Bank"
  }
}
```

#### Audio Analysis
```bash
curl -X POST http://localhost:8000/api/v1/analyze/audio \
  -H "X-API-KEY: YOUR_API_KEY" \
  -F "audio_file=@recording.wav" \
  -F "mode=shield"
```

**Request:**
- `audio_file`: Audio file (wav, mp3, m4a, ogg, flac, max 10MB)
- `mode`: Operation mode (shield/honeypot)

**Response:** Same as text analysis with additional `voice_analysis` field.

#### Dataset Statistics
```bash
curl -X GET http://localhost:8000/api/v1/dataset/stats \
  -H "X-API-KEY: YOUR_API_KEY"
```

#### Threat Campaigns
```bash
curl -X GET http://localhost:8000/api/v1/campaigns \
  -H "X-API-KEY: YOUR_API_KEY"
```

---

## 🔧 Configuration

### Environment Variables
```bash
# ─── Required ───
GEMINI_API_KEY=your-gemini-api-key
API_AUTH_KEY=your-secure-api-key

# ─── AI Providers (optional, enables multi-agent) ───
OPENAI_API_KEY=your-openai-key
GROQ_API_KEY=your-groq-key
GEMINI_MODEL=gemini-2.5-flash
OPENAI_MODEL=gpt-4o-mini
GROQ_MODEL=llama-3.3-70b-versatile

# ─── Multi-Agent Tuning ───
COGNITIVE_RISK_THRESHOLD=0.7       # risk_score threshold for scam intervention
AGENT_TIMEOUT_SECONDS=15           # per-agent LLM call timeout

# ─── Audio ───
MAX_AUDIO_MB=10
WHISPER_MODEL_SIZE=base

# ─── Honeypot ───
HONEYPOT_MAX_TURNS=5
HONEYPOT_CONFIDENCE_THRESHOLD=0.85

# ─── Performance Tuning ───
CLASSIFICATION_CACHE_MAX=256        # bounded LRU cache
CLASSIFICATION_CACHE_TTL=300        # cache TTL seconds
MAX_CONCURRENT_REQUESTS=100         # concurrency semaphore
THREAD_POOL_WORKERS=4               # audio processing threads
REQUEST_TIMEOUT_SECONDS=30
RATE_LIMIT_MAX_CLIENTS=10000        # memory-safe rate limiter

# ─── Application ───
APP_ENV=production                  # development | testing | production
LOG_LEVEL=INFO                      # DEBUG | INFO | WARNING | ERROR
CORS_ORIGINS=*                      # comma-separated origins
```

---

## 📁 Project Structure

```
BlockSafe/
├── server/
│   └── app/
│       ├── api/v1/
│       │   ├── routes.py            # FastAPI endpoints
│       │   ├── schemas.py           # Pydantic models (PolicyViolation, AIFeedback, CampaignInfo)
│       │   └── errors.py            # Custom error handlers
│       ├── core/
│       │   ├── scam_detector.py     # Main classifier (calls run_agents → legacy Gemini → rules)
│       │   ├── ssf_engine.py        # Scam Strategy Fingerprint (regex patterns)
│       │   ├── agent_swarm.py       # LangGraph 5-agent swarm (deep analysis)
│       │   ├── campaign_manager.py  # Merging Intervals threat campaign tracker
│       │   ├── honeypot.py          # Controlled scammer engagement
│       │   ├── response_builder.py  # Deterministic JSON response assembly
│       │   ├── decision_engine.py   # Risk evaluation engine
│       │   ├── dataset_manager.py   # Dynamic pattern loading
│       │   └── dataset_updater.py   # Self-learning pattern updates
│       ├── intelligence/
│       │   ├── agents.py            # LangChain multi-agent pipeline (Profiler + Fact-Checker)
│       │   ├── voice_analysis.py    # Voice signal analysis
│       │   └── speech_to_text.py    # Whisper-based transcription
│       ├── security/
│       │   ├── rate_limit.py        # Rate limiting middleware
│       │   └── auth.py              # API key authentication
│       ├── config.py                # Pydantic settings with env loading
│       └── main.py                  # Application entrypoint
├── Dockerfile                       # Multi-stage Docker build
├── docker-compose.yml               # Docker Compose with health checks
├── setup.bat / setup.sh             # Dev environment setup scripts
└── README.md                        # This file
```

---

## 🛡️ Security Features

### Authentication & Authorization
- API key-based authentication
- Rate limiting (60 req/min, 1000 req/hour)
- Input sanitization and validation

### Data Protection
- Stateless design (no persistent storage)
- Bounded honeypot execution
- No sensitive data logging
- API keys stored as `SecretStr` (never logged)

### Error Handling
- Three-tier fallback: Multi-agent → Legacy Gemini → Rule-based
- Risk-based confidence calibration
- Comprehensive error responses

---

## 🧪 Testing

### Unit Tests
```bash
cd server
python -m pytest tests/ -v
```

### API Testing Examples

**Bank Impersonation (Scam):**
```bash
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: YOUR_API_KEY" \
  -d '{"message": "SBI Bank Alert: Your account is restricted due to pending KYC. Update PAN immediately via sbi-kyc-update.info or your account will be blocked in 15 mins.", "mode": "shield"}'
```

**Card Fraud Detection:**
```bash
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: YOUR_API_KEY" \
  -d '{"message": "Please share your 16 digit card number and CVV"}'
```

**Benign Message (No Scam):**
```bash
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: YOUR_API_KEY" \
  -d '{"message": "Hi, I wanted to confirm our meeting scheduled for tomorrow at 3 PM. Let me know if the time works."}'
```

### Supported Scam Types
| Type | Description |
|------|-------------|
| `card_fraud` | Credit/debit card information requests |
| `bank_impersonation` | Fake bank official communications |
| `upi_fraud` | UPI payment manipulation |
| `phishing` | Credential harvesting attempts |
| `government_impersonation` | Fake authority communications |
| `tech_support_scam` | Fake technical support scams |
| `investment_scam` | Fraudulent investment schemes |
| `romance_scam` | Relationship-based fraud |
| `job_scam` | Fake employment offers |
| `loan_scam` | Advance fee loan scams |

### Evidence Levels
| Level | Meaning |
|-------|---------|
| `NONE` | No risk indicators detected |
| `LOW` | Financial entities detected, no manipulation |
| `MEDIUM` | Moderate scam indicators present |
| `HIGH` | Strong scam indicators with high confidence |

---

## 📦 Deployment

### Docker Compose (Recommended)
```bash
# Start with build
docker compose up --build

# Background mode
docker compose up --build -d

# Tail logs
docker compose logs -f

# Shutdown
docker compose down
```

Docker Compose includes resource limits (2 GB memory, 2 CPUs), health checks, and automatic restarts.

### Docker Manual
```bash
# Build multi-stage image
docker build -t blocksafe:latest .

# Run with environment file
docker run -d -p 8000:8000 --env-file server/.env blocksafe:latest

# Run with inline environment (multi-agent mode)
docker run -d -p 8000:8000 \
  -e GEMINI_API_KEY=your-key \
  -e API_AUTH_KEY=your-key \
  -e OPENAI_API_KEY=your-openai-key \
  -e GROQ_API_KEY=your-groq-key \
  blocksafe:latest
```

### Health Monitoring
```bash
# Health endpoint
curl http://localhost:8000/health

# Check container status
docker ps

# View logs
docker compose logs -f blocksafe-api
```

---

## 🔄 Continuous Chat Sessions

BlockSafe supports continuous conversations through session management:

```bash
# Start session
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: YOUR_API_KEY" \
  -d '{
    "message": "Hello, I need help with my account",
    "session_id": "user-session-123"
  }'

# Continue session
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: YOUR_API_KEY" \
  -d '{
    "message": "Can you tell me your card number?",
    "session_id": "user-session-123"
  }'
```

---

## 📊 Monitoring & Analytics

### Dataset Statistics
Monitor scam pattern evolution:
```bash
curl -X GET http://localhost:8000/api/v1/dataset/stats \
  -H "X-API-KEY: YOUR_API_KEY"
```

### Threat Campaign Tracking
View all tracked scam campaigns:
```bash
curl -X GET http://localhost:8000/api/v1/campaigns \
  -H "X-API-KEY: YOUR_API_KEY"
```

### Response Analysis
- **Cognitive Risk Scores**: `fear_score`, `urgency_score`, `authority_score`
- **Policy Violations**: Real-time entity verification against known policies
- **Provider Tracking**: `provider_used` shows which AI engine handled the request
- **Campaign Intelligence**: `campaign_info` links attempts to tracked threat campaigns

---

## 🚨 Important Notes

### Security Considerations
- Never commit API keys to version control
- Use strong, unique API authentication keys
- Monitor rate limits and usage patterns
- Regularly update dependencies

### Limitations
- Requires internet connection for AI provider APIs
- Audio processing limited to 10MB files
- Honeypot mode has built-in safety limits
- Classification accuracy depends on AI provider availability

### Support
- Check logs for debugging: `docker logs blocksafe-container`
- Verify API key validity and quotas
- Ensure proper network connectivity
- Review rate limiting if requests fail

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

---

**BlockSafe** — Protecting users from financial scams through multi-agent AI detection and intelligence gathering.
