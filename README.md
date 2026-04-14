# SecureShield AI Gateway 🛡️

SecureShield is an enterprise-grade AI Middleware and Proxy designed to protect organizational data when interacting with Large Language Models (LLMs). It acts as a "Bouncer" for AI requests, ensuring that sensitive information never leaves the company network and that malicious prompts are blocked before they reach the AI.

## 🚀 Features

- **Universal LLM Gateway**: Seamlessly switch between OpenRouter (Gemma 2, GPT-4, Llama) and Google Gemini with automatic failover.
- **6-Layer Security Pipeline**:
    1. **Normalization**: Detects obfuscated attacks.
    2. **Intent Classification**: Uses AI to predict malicious user intent.
    3. **Rule Engine**: Fast, regex-based check for known threats.
    4. **PII Detection**: Automatically redacts sensitive data (SSNs, Emails, Phones).
    5. **Semantic Security**: Compares prompts against a database of known injection techniques.
    6. **Output Guard**: Monotors AI responses to prevent data leakage.
- **Cyber-Secure Dashboard**: Real-time analytics, risk scoring, and security event logging.
- **Enterprise-Ready**: Optimized for the Gemma 2 family (Gamma 4) for high-performance, private deployments.

## 🛠️ Tech Stack

- **Backend**: Python (Flask), PyMongo, OpenAI SDK, Microsoft Presidio.
- **Frontend**: React, Tailwind CSS, Recharts, Lucide Icons.
- **Database**: MongoDB (NoSQL).
- **AI Models**: Gemma 2 9B (via OpenRouter), Gemini 1.5 Flash.

## 📦 Installation

### Prerequisites
- Python 3.8+
- Node.js & npm
- MongoDB (Running on port 27017)

### Setup
1. **Clone the repository**:
   ```bash
   git clone https://github.com/NiketaTembhare/SecureShield-AI.git
   cd SecureShield-AI
   ```

2. **Backend Setup**:
   ```bash
   cd secureSheild/backend
   pip install -r requirements.txt
   # Configure your .env file with API keys
   python app.py
   ```

3. **Frontend Setup**:
   ```bash
   cd secureSheild/frontend
   npm install
   npm run dev
   ```

## 📄 License
MIT License - Proprietary for Enterprise Use Cases.
