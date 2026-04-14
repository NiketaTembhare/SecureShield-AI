import pytest
from services.risk_engine import compute_decision, RiskDecision

def test_safe_request():
    result = compute_decision(
        rule_score=0.0,
        semantic_score=0.2,
        intent="SAFE",
        pii_score=0.0,
        pii_detected=False,
        policy_score=0.0,
        policy_allowed=True,
        attack_type=None
    )
    assert result.decision == "ALLOW"
    assert result.risk_score == 0

def test_policy_violation_is_hard_block():
    result = compute_decision(
        rule_score=0.0,
        semantic_score=0.1,
        intent="SAFE",
        pii_score=0.0,
        pii_detected=False,
        policy_score=0.5,
        policy_allowed=False,  # BLOCKED!
        attack_type=None
    )
    assert result.decision == "BLOCK"
    assert result.risk_score >= 5
    assert result.message == "Blocked by access control policy."

def test_accumulated_risk_block():
    # Rule=0.8 (+5 pts), Intent="INJECTION" (+5 pts) => Total 10 (>= 7 is BLOCK)
    result = compute_decision(
        rule_score=0.8,
        semantic_score=0.2,
        intent="INJECTION",
        pii_score=0.0,
        pii_detected=False,
        policy_score=0.0,
        policy_allowed=True,
        attack_type="PROMPT_INJECTION"
    )
    assert result.decision == "BLOCK"
    assert result.risk_score >= 7

def test_warning_threshold():
    # Semantic=0.75 (+4 pts) => Total 4 (>= 4 is WARN)
    result = compute_decision(
        rule_score=0.0,
        semantic_score=0.75,
        intent="SAFE",
        pii_score=0.0,
        pii_detected=False,
        policy_score=0.0,
        policy_allowed=True,
        attack_type=None
    )
    assert result.decision == "WARN"
    assert result.risk_score == 4
