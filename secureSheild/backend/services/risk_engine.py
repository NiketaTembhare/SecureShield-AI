from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class RiskDecision:
    decision: str           # BLOCK | WARN | ALLOW
    risk_score: int         # 0–26 integer (explainable, spec-compliant)
    risk_pct: float         # 0.0–1.0 normalised (for frontend display / logging)
    attack_type: Optional[str]
    message: str
    contributing_factors: list[str]   # human-readable audit trail


# ── Score weights (integer points, max sum = 26) ──────────────────────────────
#
#  Layer              Max pts   Rationale
#  ─────────────────────────────────────────────────────────────────────────
#  Rule engine          5       Hard-coded pattern → high precision signal
#  Semantic similarity  4       Embedding distance → covers obfuscation
#  LLM intent           5       Contextual reasoning → catches nuanced attacks
#  PII detected         7       Sensitive data presence → DLP hard block
#  Policy violation     5       Access control breach → always serious
#  ─────────────────────────────────────────────────────────────────────────
#  TOTAL               26
#
# Decision thresholds (per spec):
#   score >= 7  → BLOCK
#   score >= 4  → WARN
#   else        → ALLOW

_MAX_RULE     = 5
_MAX_SEMANTIC = 4
_MAX_INTENT   = 5
_MAX_PII      = 7
_MAX_POLICY   = 5
_MAX_TOTAL    = _MAX_RULE + _MAX_SEMANTIC + _MAX_INTENT + _MAX_PII + _MAX_POLICY  # 26

_THRESHOLD_BLOCK = 7
_THRESHOLD_WARN  = 4


def _rule_points(rule_score: float) -> tuple[int, str]:
    """Any rule engine hit is treated as a strong attack signal."""
    if rule_score > 0.0:
        return 5, f"Rule hit (score={rule_score:.2f}) → +5"
    return 0, ""


def _semantic_points(semantic_score: float) -> tuple[int, str]:
    """Semantic similarity above the configured threshold adds strong risk."""
    if semantic_score >= 0.70:
        return 4, f"Semantic score={semantic_score:.2f} → +4"
    return 0, ""


def _intent_points(intent: Optional[str]) -> tuple[int, str]:
    """LLM intent classification contributes a strong security weight."""
    if not intent or intent == "SAFE":
        return 0, ""
    return 5, f"Intent={intent} → +5"


def _pii_points(pii_score: float, pii_detected: bool) -> tuple[int, str]:
    """PII presence adds a hard block weight (DLP policy)."""
    if not pii_detected:
        return 0, ""
    return 7, f"PII detected (score={pii_score:.2f}) → +7"


def _policy_points(policy_allowed: bool, policy_score: float) -> tuple[int, str]:
    """Policy violations are a hard enterprise gate."""
    if not policy_allowed:
        return 5, f"Policy violation (score={policy_score:.2f}) → +5"
    return 0, ""


def compute_decision(
    *,
    rule_score: float,
    semantic_score: float,
    intent_score: float = 0.0,    # kept for backward-compat; use intent kwarg instead
    pii_score: float,
    policy_score: float,
    policy_allowed: bool,
    attack_type: Optional[str],
    # New: pass the string intent label for precise point mapping
    intent: Optional[str] = None,
    pii_detected: bool = False,
) -> RiskDecision:
    """
    Compute an integer risk score (0–26) and make a BLOCK / WARN / ALLOW decision.

    Args:
        rule_score      : Highest rule engine match score (0.0–1.0).
        semantic_score  : Best cosine similarity from semantic scan (0.0–1.0).
        intent_score    : Legacy float intent score (kept for backward compat).
        pii_score       : PII detection confidence (0.0–1.0).
        policy_score    : Policy engine violation score (0.0–1.0).
        policy_allowed  : False if access policy blocks this request.
        attack_type     : String label from rule engine / classifier.
        intent          : String intent from LLM classifier (preferred over intent_score).
        pii_detected    : Whether PII was found in the input.
    """
    factors: list[str] = []

    # ── Hard gate: policy violation bypasses scoring ──────────────────────────
    if not policy_allowed:
        p_pts, p_msg = _policy_points(policy_allowed, policy_score)
        return RiskDecision(
            decision="BLOCK",
            risk_score=max(_THRESHOLD_BLOCK, p_pts),
            risk_pct=1.0,
            attack_type=attack_type or "POLICY_VIOLATION",
            message="Blocked by access control policy.",
            contributing_factors=[p_msg, "Hard policy gate triggered"],
        )

    # ── Accumulate points ─────────────────────────────────────────────────────
    r_pts,  r_msg  = _rule_points(rule_score)
    s_pts,  s_msg  = _semantic_points(min(1.0, semantic_score))

    if intent is not None:
        i_pts, i_msg = _intent_points(intent)
    else:
        # Legacy compatibility: if no explicit intent label is available, map coarse float.
        if intent_score >= 0.75:
            legacy_intent = "JAILBREAK"
        elif intent_score >= 0.65:
            legacy_intent = "DATA_EXTRACTION"
        elif intent_score >= 0.60:
            legacy_intent = "INJECTION"
        else:
            legacy_intent = "SAFE"
        i_pts, i_msg = _intent_points(legacy_intent)

    pi_pts, pi_msg = _pii_points(pii_score, pii_detected)
    po_pts, po_msg = _policy_points(policy_allowed, policy_score)

    total = min(_MAX_TOTAL, r_pts + s_pts + i_pts + pi_pts + po_pts)

    for msg in (r_msg, s_msg, i_msg, pi_msg, po_msg):
        if msg:
            factors.append(msg)

    risk_pct = round(total / _MAX_TOTAL, 4)

    # ── Decision ──────────────────────────────────────────────────────────────
    # Evaluate explicitly what caused the block for concise UI feedback
    primary_reason = factors[0] if factors else "Unclassified heuristic trigger"
    
    # ── Decision ──────────────────────────────────────────────────────────────
    if total >= _THRESHOLD_BLOCK:
        return RiskDecision(
            decision="BLOCK",
            risk_score=total,
            risk_pct=risk_pct,
            attack_type=attack_type,
            message=f"Request blocked. Reason: {primary_reason}.",
            contributing_factors=factors,
        )
    if total >= _THRESHOLD_WARN:
        return RiskDecision(
            decision="WARN",
            risk_score=total,
            risk_pct=risk_pct,
            attack_type=attack_type,
            message=f"Warning: Suspicious request. Primary concern: {primary_reason}.",
            contributing_factors=factors,
        )
    return RiskDecision(
        decision="ALLOW",
        risk_score=total,
        risk_pct=risk_pct,
        attack_type=attack_type,
        message="Allowed.",
        contributing_factors=factors,
    )