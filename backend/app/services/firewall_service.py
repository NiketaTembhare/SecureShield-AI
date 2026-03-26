import datetime
from app.database.mongo import db
from app.models.prompt import DetectionResult

BLOCKED_PHRASES = [
    "system override",
    "ignore previous instruction",
    "forget previous instruction",
    "you are now",
    "jailbreak"
]

async def scan_prompt(prompt: str, user_id: str, department: str) -> DetectionResult:
    prompt_lower = prompt.lower()
    
    # Validation constraint checking for injection keywords
    for phrase in BLOCKED_PHRASES:
        if phrase in prompt_lower:
            await log_security_event(prompt, "Prompt Injection", f"Triggered by phrase: '{phrase}'", user_id, department)
            return DetectionResult(
                is_blocked=True,
                reason="Prompt Injection Detected. Request Blocked."
            )
            
    return DetectionResult(
        is_blocked=False,
        response=f"This is a simulated secure response to: '{prompt}'"
    )

async def log_security_event(prompt: str, attack_type: str, details: str, user_id: str, department: str):
    log_entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc),
        "prompt": prompt,
        "attack_type": attack_type,
        "details": details,
        "user_id": user_id,
        "department": department
    }
    try:
        await db.security_logs.insert_one(log_entry)
        print(f"[SECURITY LOG]: {attack_type} saved to DB for user {user_id} in {department}.")
    except Exception as e:
        print(f"[DB WARNING]: Could not save to MongoDB. Is MongoDB running on 27017? Error: {e}")
