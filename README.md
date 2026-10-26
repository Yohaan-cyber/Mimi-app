# Mimi — WhatsApp Scam & Fraud Detection Agent

Mimi is an AI-powered WhatsApp bot that detects and flags scams, fraud, and phishing attempts in real time.

## Features
- Scam detection via Groq LLM (text, audio, links)
- URL scanning via VirusTotal
- Voice message transcription via AWS Transcribe / Groq Whisper
- Trusted contact alerts for high-risk situations
- Multilingual support

## Setup

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/scam-detector.git
cd scam-detector
```

### 2. Create a virtual environment
```bash
python -m venv venv
venv\Scripts\activate      # Windows
# or
source venv/bin/activate   # macOS/Linux
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment
```bash
cp .env.example .env
# Edit .env and fill in your API keys
```

### 5. Configure trusted contacts
```bash
cp trusted_contacts.example.json trusted_contacts.json
# Edit trusted_contacts.json with real numbers
```

### 6. Run
```bash
python main.py
```

## Requirements
- Python 3.11+
- Twilio account (WhatsApp sandbox or approved sender)
- Groq API key
- AWS account (S3 + Transcribe)
- VirusTotal API key

## Security
Never commit `.env` or `trusted_contacts.json` — both are in `.gitignore`.
