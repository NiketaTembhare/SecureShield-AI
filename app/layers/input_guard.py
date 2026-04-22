def check_input(text: str) -> bool:
    # Now that we stripped the hyphens, "h-a-c-k" becomes "hack"
    # Expanded patterns to catch instruction-bypass attempts
    blocked_patterns = [
        "hack", "attack", "bypass", "ignore previous", "ignore instructions",
        "forget all previous", "system prompt", "developer mode", "jailbreak",
        "dan mode", "act as", "disregard instructions", "reveal secret"
    ]
    
    for pattern in blocked_patterns:
        if pattern in text: # No longer need .lower() as normalizer did it
            return False
    return True