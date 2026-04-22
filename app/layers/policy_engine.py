def check_policy(message: str, user_role: str) -> bool:
    # Policy Engine now focuses on "Intent-based Blocking"
    # Data tokens (server names, etc.) are handled by the Redactor (PII Guard)
    
    malicious_intents = [
        "bypass security", "exploit", "drop database", "sudo rm",
        "show secret key", "reveal admin", "give me the password",
        "extract auth token", "list all users", "access restricted data"
    ]
    
    if any(intent in message.lower() for intent in malicious_intents):
        return False
        
    return True
