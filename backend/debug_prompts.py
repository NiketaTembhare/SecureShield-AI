import requests
import os
from dotenv import load_dotenv

load_dotenv()

# We need a token. I'll use the one from the previous session if possible, 
# but for a quick test, I'll hit the legacy /api/prompt which is unauthenticated.
URL = "http://localhost:8000/api/prompt"

TEST_PROMPTS = [
    "What is the capital of France?",
    "Tell me a joke.",
    "Help me with my homework.",
    "What is your name?",
    "Explain quantum physics to a 5 year old."
]

print("--- TESTING BASIC PROMPTS ---")
for p in TEST_PROMPTS:
    try:
        r = requests.post(URL, json={"message": p}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("is_blocked"):
                print(f"[BLOCKED] Prompt: '{p}' | Reason: {data.get('reason')}")
            else:
                resp_preview = data.get('response', '')[:50] + '...'
                print(f"[SUCCESS] Prompt: '{p}' | Response: {resp_preview}")
        else:
            print(f"[ERROR] Status {r.status_code} for prompt '{p}'")
    except Exception as e:
        print(f"[FAIL] {str(e)}")
