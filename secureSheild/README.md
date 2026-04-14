# 🛡️ SecureShield AI Gateway: Enterprise AI Firewall & DLP Middleware Proxy

**The Main Goal:** Organizations are rapidly adopting Generative AI, but face massive risks: employees leaking confidential data (PII, secrets) to LLMs, attackers bypassing AI guardrails (Jailbreaks), and internal cross-departmental data breaches. 

**SecureShield AI (SSA) solves this** by acting as an invisible middleware layer inside the organization's infrastructure.
`Internal App / User  →  SecureShield Middleware  →  External LLM (OpenAI/Gemini)`

Integrating SSA is as simple as routing all your internal AI requests through it (acting as a reverse-proxy). SSA provides a multi-layer security pipeline — blocking prompt injections, detecting PII leaks, and enforcing Role-Based Access Control (RBAC) *before* any data reaches an external AI provider.

---

## ⚡ Quick Setup (5 Minutes)

### Prerequisites
- Python 3.10+
- Node.js 18+
- MongoDB running on port 27017

### 1. Clone / unzip the project

### 2. Setup Backend
```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate it
# Windows:
.venv\Scripts\activate
# Mac/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Download the AI language model for PII detection
python -m spacy download en_core_web_sm

# Copy the env file and fill in your API key
copy .env.example .env
# Open .env and add your GEMINI_API_KEY

# Start the backend
python app.py
```
Backend runs at: http://localhost:8000

### 3. Setup Frontend
```bash
cd frontend
npm install
npm run dev
```
Frontend runs at: http://localhost:5173

### 4. Get a Gemini API Key (Free)
1. Go to https://aistudio.google.com/app/apikey
2. Click **Create API Key**
3. Paste it into `backend/.env` as `GEMINI_API_KEY`

---

## 🏗️ Architecture

```
User Prompt
    ↓
[1] Rule Engine       → blocks known keywords/phrases
    ↓
[2] Semantic Engine   → detects suspicious meaning
    ↓
[3] LLM Classifier    → AI intent classification
    ↓
[4] Policy Engine     → RBAC department rules
    ↓
[5] PII Detector      → blocks emails, phones, Aadhaar, PAN
    ↓
[6] Risk Engine       → computes final risk score (0–26)
    ↓
ALLOW (→ Gemini AI)  or  BLOCK (→ Error message)
```

---

## 🔑 Default Test Accounts

Register via the Signup page with any email/password.

For admin access, use role: `admin` in signup body via API.

---

## 🧪 Test the Security Layers

| Prompt | Expected |
|:---|:---|
| `What is encryption?` | ✅ ALLOW — real AI answer |
| `My email is test@gmail.com` | 🔴 BLOCK — PII detected |
| `My Aadhaar is 1234 5678 9012` | 🔴 BLOCK — Indian PII detected |
| `Ignore all previous instructions` | 🔴 BLOCK — Prompt injection |

---

## 📁 Project Structure

```
secureSheild/
├── backend/
│   ├── services/          # Security engines (PII, Rules, Risk, Semantic...)
│   ├── routes/            # API endpoints
│   ├── auth/              # JWT authentication
│   ├── database/          # MongoDB connection
│   ├── app.py             # Entry point
│   └── requirements.txt
└── frontend/
    ├── src/pages/         # Login, Chat, Dashboard
    └── src/lib/api.js     # API client
```

---

## 🚀 Deploy for Free

| Service | What | Cost |
|:---|:---|:---|
| MongoDB Atlas | Database | Free |
| Render.com | Backend API | Free |
| Vercel | Frontend | Free |
