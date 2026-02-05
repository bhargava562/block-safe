# BlockSafe - AI-Powered Scam Detection System

[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://docker.com)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-green)](https://fastapi.tiangolo.com)
[![Gemini](https://img.shields.io/badge/Gemini-2.5%20Flash-orange)](https://ai.google.dev)

> **Live API Endpoint**: `https://blocksafe-latest.onrender.com/api/v1/analyze/text`

BlockSafe is a production-ready AI system for real-time scam detection and intelligence extraction. It provides both defensive (Shield) and intelligence gathering (Honeypot) capabilities with multi-modal analysis supporting text and audio inputs.

## 🚀 Quick Start

### Prerequisites
- Docker installed
- Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey)

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
  "timestamp": "2026-02-05T07:35:13Z"
}
```

#### Text Analysis
```bash
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: YOUR_API_KEY" \
  -d '{
    "message": "Tell your 16 digits card number",
    "mode": "shield",
    "session_id": "optional-session-id"
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
  "timestamp": "2026-02-05T07:35:13Z",
  "is_scam": true,
  "confidence": 0.95,
  "scam_type": "card_fraud",
  "transcript": null,
  "original_message": "Tell your 16 digits card number",
  "extracted_entities": {
    "upi_ids": [],
    "bank_accounts": [],
    "urls": [],
    "phone_numbers": []
  },
  "ssf_profile": {
    "urgency_score": 0.0,
    "authority_claims": [],
    "payment_escalation": false,
    "channel_switch_intent": null,
    "urgency_phrases": [],
    "strategy_summary": "Direct payment request without advanced social-engineering patterns"
  },
  "voice_analysis": null,
  "honeypot_result": null,
  "agent_summary": "High-confidence card fraud detected. Shield mode active: user protected without engagement.",
  "evidence_level": "HIGH",
  "operation_mode": "shield"
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

## 🔧 Configuration

### Environment Variables
```bash
# Required
GEMINI_API_KEY=your-gemini-api-key
API_AUTH_KEY=your-secure-api-key

# Optional
MAX_AUDIO_MB=10
HONEYPOT_MAX_TURNS=5
HONEYPOT_CONFIDENCE_THRESHOLD=0.85
```

### Supported Scam Types
- `card_fraud` - Credit/debit card information requests
- `bank_impersonation` - Fake bank official communications
- `upi_fraud` - UPI payment manipulation
- `phishing` - Credential harvesting attempts
- `government_impersonation` - Fake authority communications
- `tech_support_scam` - Fake technical support
- `investment_scam` - Fraudulent investment schemes
- `romance_scam` - Relationship-based fraud
- `job_scam` - Fake employment offers

### Evidence Levels
- `NONE` - No risk indicators
- `LOW` - Financial entities detected, no manipulation
- `MEDIUM` - Moderate scam indicators
- `HIGH` - Strong scam indicators with high confidence

## 🏗️ Architecture

### System Components
- **FastAPI Server** - Async web framework with authentication
- **Gemini AI** - Advanced language model for classification
- **Entity Extraction** - Regex-based financial entity detection
- **SSF Engine** - Scam Strategy Fingerprinting
- **Honeypot Agent** - Controlled scammer engagement
- **Dataset Manager** - Dynamic pattern learning

### Performance Characteristics
- **Text Analysis**: < 1 second average
- **Audio Analysis**: < 30 seconds (including transcription)
- **Concurrent Requests**: 100+ supported
- **Rate Limiting**: 60 req/min per API key

## 🛡️ Security Features

### Authentication & Authorization
- API key-based authentication
- Rate limiting (60 req/min, 1000 req/hour)
- Input sanitization and validation

### Data Protection
- Stateless design (no persistent storage)
- Bounded honeypot execution
- No sensitive data logging

### Error Handling
- Graceful degradation on AI failures
- Risk-based confidence calibration
- Comprehensive error responses

## 🧪 Testing

### Unit Tests
```bash
cd server
python -m pytest tests/ -v
```

### API Testing Examples

**Card Fraud Detection:**
```bash
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: YOUR_API_KEY" \
  -d '{"message": "Please share your 16 digit card number and CVV"}'
```

**UPI Fraud Detection:**
```bash
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: YOUR_API_KEY" \
  -d '{"message": "GPay Rs 500 to scammer@ybl immediately"}'
```

**Legitimate Payment Request:**
```bash
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: YOUR_API_KEY" \
  -d '{"message": "GPay the amount of 25 in this contact number 635352423"}'
```

## 📦 Deployment

### Docker Production
```bash
# Build
docker build -t blocksafe:latest .

# Run with environment file
docker run -d -p 8000:8000 --env-file .env blocksafe:latest

# Run with inline environment
docker run -d -p 8000:8000 \
  -e GEMINI_API_KEY=your-key \
  -e API_AUTH_KEY=your-key \
  blocksafe:latest
```

### IntelliJ IDEA Setup
1. **Run Configuration**: Docker → Image
2. **Image**: `blocksafe:latest`
3. **Port**: `8000:8000`
4. **Environment Variables**: Set GEMINI_API_KEY and API_AUTH_KEY
5. **Run Options**: `--rm`

### Health Monitoring
```bash
# Check container status
docker ps

# View logs
docker logs blocksafe-container

# Health endpoint
curl http://localhost:8000/health
```

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

## 📊 Monitoring & Analytics

### Dataset Statistics
Monitor scam pattern evolution:
```bash
curl -X GET http://localhost:8000/api/v1/dataset/stats \
  -H "X-API-KEY: YOUR_API_KEY"
```

### Response Analysis
- **Evidence Levels**: Track risk distribution
- **Confidence Scores**: Monitor detection accuracy
- **Entity Extraction**: Analyze threat indicators
- **Session Patterns**: Understand conversation flows

## 🚨 Important Notes

### Security Considerations
- Never commit API keys to version control
- Use strong, unique API authentication keys
- Monitor rate limits and usage patterns
- Regularly update dependencies

### Limitations
- Requires internet connection for Gemini API
- Audio processing limited to 10MB files
- Honeypot mode has built-in safety limits
- Classification accuracy depends on training data

### Support
- Check logs for debugging: `docker logs blocksafe-container`
- Verify API key validity and quotas
- Ensure proper network connectivity
- Review rate limiting if requests fail

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

---

**BlockSafe** - Protecting users from financial scams through advanced AI detection and intelligence gathering.
