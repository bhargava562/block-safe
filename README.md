<!-- Generate a professional, judge-friendly root README.md based strictly on the following context. This is a high-level API showcase, not a technical deep dive. -->
# BlockSafe
*Agentic AI system for real-time scam detection & intelligence extraction*

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11-blue" />
  <img src="https://img.shields.io/badge/FastAPI-0.110-green" />
  <img src="https://img.shields.io/badge/Gemini-2.0%20Flash-orange" />
  <img src="https://img.shields.io/badge/Scam%20Detection-AI--Powered-red" />
  <img src="https://img.shields.io/badge/Mode-Shield%20%7C%20Honeypot-purple" />
  <img src="https://img.shields.io/badge/Stateless-Yes-success" />
  <img src="https://img.shields.io/badge/Docker-Ready-blue" />
  <img src="https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-black" />
</p>

🔒🚀 BlockSafe is a production-grade, agentic AI service that flags scams in real time, fingerprints tactics, and responds in Shield or Honeypot modes—built to impress hackathon judges and API consumers in under 30 seconds.

## 🎯 What BlockSafe Does
- 🎙️ Accepts text or audio inputs.
- 🧠 Detects scams using Gemini 2.0 Flash.
- 🪪 Generates Scam Strategy Fingerprints (SSF).
- 🛡️ Operates in Shield mode (defensive) or 🍯 Honeypot mode (intelligence extraction).
- 📦 Returns deterministic JSON for evaluation.

## ⚡ API First — Quick Start
**Base URL:** `https://api.blocksafescan.ai`  
**Auth header:** `X-API-KEY: <YOUR_API_KEY>`
- 🔑 API key is required.
- 🧾 Responses are JSON.
- ♻️ Stateless design.

Example request (conceptual):
```http
POST /v1/scan HTTP/1.1
Host: api.blocksafescan.ai
X-API-KEY: <YOUR_API_KEY>
Content-Type: application/json

{ "input": "voice or text payload", "mode": "shield|honeypot" }

```

## 🗺️ Architecture (High-Level)
```mermaid
flowchart TD
  %% Client and Entry Layer
  A[Client] -->|POST /v1/scan| B[Auth & Rate Limit]
  
  %% Intake Layer
  B --> C{Intake Type}
  C -->|Text| D[Sanitization]
  C -->|Audio| E[Whisper Transcription]
  E --> F[Voice Signal Analysis]
  
  %% AI Core Analysis Layer
  D --> G[Gemini 2.0 Flash Classifier]
  F --> G
  G --> H[SSF Engine]
  
  %% Decision & Mode Selection Layer
  H --> I{Decision Engine}
  I -->|Confidence < Threshold| J[Shield Reply]
  I -->|Confidence >= Threshold| K{Operation Mode}
  
  %% Mode Specific Logic
  K -->|Shield| L[Defensive Response]
  K -->|Honeypot| M[Autonomous Agentic Engagement]
  
  %% Intelligence & Response Layer
  L --> N[Response Builder]
  M --> N
  N --> O[Structured JSON Response]
  
  %% Styling
  style G fill:#f96,stroke:#333,stroke-width:2px
  style M fill:#bbf,stroke:#333,stroke-width:2px
  style O fill:#dfd,stroke:#333,stroke-width:2px
```

## 📁 Repository Structure
/
├── server/        # Backend implementation (detailed README inside)
├── .github/       # CI/CD workflows
├── docker/        # Docker-related files (optional grouping)
├── README.md      # This file

- Server README contains full technical details.
- Root README is intentionally high-level.

## 🐳 Docker Support
- Dockerfiles are provided for containerized deployment.
- `.dockerignore` keeps images lean.
- Cloud-ready footprint.

## 🤖 CI/CD Support
- GitHub Actions workflows live under `.github/workflows`.
- CI validates Python version, dependency install, and app startup sanity for judge reproducibility.

## 🛡️ Security & Ethics
- No data is stored; processing is stateless.
- Honeypot mode is bounded and controlled.
- Designed for defensive cybersecurity research.

## 📣 Call to Action
See `server/README.md` for full technical implementation.  
Designed for hackathons, extensible for production.
