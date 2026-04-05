from dataclasses import dataclass
from typing import Optional


@dataclass
class PolicyResult:
    allowed: bool
    reason: Optional[str]
    score: float


def evaluate_policy(*, department: str, role: str, prompt: str) -> PolicyResult:
    """
    Simple RBAC example:
    - HR cannot request finance payroll/budget details unless role=admin.
    - Finance cannot request HR medical details unless role=admin.
    """
    dep = (department or "").strip().lower()
    r = (role or "").strip().lower()
    p = (prompt or "").lower()

    if r == "admin":
        return PolicyResult(allowed=True, reason=None, score=0.0)

    if dep == "hr" and any(k in p for k in ["salary", "payroll", "budget", "revenue", "profit", "finance", "finance report", "compensation"]):
        return PolicyResult(allowed=False, reason="HR policy: finance and salary data access restricted", score=0.45)

    if dep == "finance" and any(k in p for k in ["medical", "diagnosis", "health record", "hr file", "personnel file", "employee medical"]):
        return PolicyResult(allowed=False, reason="Finance policy: HR sensitive data restricted", score=0.45)

    return PolicyResult(allowed=True, reason=None, score=0.0)

