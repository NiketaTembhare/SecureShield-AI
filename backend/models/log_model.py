from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class SecurityLog:
    user_id: str
    department: str
    role: str
    prompt: str
    decision: str
    risk_score: float
    attack_type: Optional[str]
    pii_detected: bool
    timestamp: datetime

