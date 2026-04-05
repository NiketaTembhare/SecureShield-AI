import datetime
from typing import Any, Dict, Optional

from flask import Blueprint, current_app, request

from auth.jwt_handler import decode_access_token
from database.mongo import get_db
from services.normalization import normalize_text
from services.rule_engine import primary_attack_type, run_rules, max_rule_score
from services.semantic_engine import semantic_scan
from services.llm_classifier import classify_intent
from services.policy_engine import evaluate_policy
from services.pii_detector import detect_and_redact
from services.risk_engine import compute_decision
from services.llm_service import chat_completion
from services.output_guard import guard_output
from extensions import limiter

chat_bp = Blueprint("chat", __name__)


def _require_auth() -> Dict[str, Any]:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise PermissionError("missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    return decode_access_token(
        token=token,
        secret=current_app.config["JWT_SECRET"],
        issuer=current_app.config["JWT_ISSUER"],
    )


def _logs_col():
    return get_db()["security_logs"]


def _run_pipeline(
    prompt: str,
    user_id: str,
    department: str,
    role: str,
) -> Dict[str, Any]:
    """
    Full security pipeline. Returns a flat dict consumed by both /chat and /prompt.

    Flow:
      Normalize → Rules → Semantic → (LLM Classifier if suspicious) →
      Policy → PII → Risk → Decision
    """

    # ── 1. Normalize ──────────────────────────────────────────────────────────
    normalized = normalize_text(prompt)

    # ── 2. Rule engine ────────────────────────────────────────────────────────
    rule_hits  = run_rules(normalized)
    rule_score = max_rule_score(rule_hits)
    attack_type = primary_attack_type(rule_hits)

    # ── 3. Semantic engine ────────────────────────────────────────────────────
    sem = semantic_scan(normalized)

    # ── 4. LLM intent classifier (only when suspicious — saves API calls) ─────
    suspicious = (rule_score >= 0.50) or sem.is_suspicious
    if suspicious:
        clf = classify_intent(
            normalized,
            rule_attack_type=attack_type,
            semantic_score=sem.score,
        )
    else:
        clf = classify_intent("", rule_attack_type=None, semantic_score=0.0)

    # Use the rule engine attack type if classifier returned SAFE but rules fired
    resolved_attack = clf.intent if clf.intent != "SAFE" else (attack_type or None)

    # ── 5. Policy engine ──────────────────────────────────────────────────────
    policy = evaluate_policy(department=department, role=role, prompt=normalized)

    # ── 6. PII detection + redact (before LLM call) ───────────────────────────
    pii = detect_and_redact(prompt)

    # ── 7. Risk scoring + decision ────────────────────────────────────────────
    decision = compute_decision(
        rule_score=rule_score,
        semantic_score=min(1.0, sem.score),
        intent_score=0.0,               # legacy field; kept for compat
        pii_score=pii.score,
        policy_score=policy.score,
        policy_allowed=policy.allowed,
        attack_type=resolved_attack,
        intent=clf.intent,              # new: string label for precise scoring
        pii_detected=pii.detected,
    )

    return {
        "normalized": normalized,
        "rule_score": rule_score,
        "attack_type": resolved_attack,
        "sem_score": sem.score,
        "sem_matched": sem.matched_example,
        "clf_intent": clf.intent,
        "clf_confidence": clf.confidence,
        "clf_rationale": clf.rationale,
        "clf_used_llm": getattr(clf, "used_llm", False),
        "policy_allowed": policy.allowed,
        "policy_reason": policy.reason,
        "pii_detected": pii.detected,
        "pii_entities": pii.entities,
        "pii_redacted": pii.redacted_text,
        "decision": decision,
    }


@chat_bp.post("/chat")
@limiter.limit("10 per minute")
def chat():
    """
    Authenticated chat endpoint.
    Flow: Auth → Pipeline → (BLOCK early return) → LLM → Output Guard → Log
    """
    try:
        claims = _require_auth()
    except Exception:
        return {"error": "unauthorized"}, 401

    body   = request.get_json(silent=True) or {}
    prompt = (body.get("message") or body.get("prompt") or "").strip()
    if not prompt:
        return {"error": "message required"}, 400

    user_id    = claims.get("user_id") or claims.get("sub") or "unknown"
    department = claims.get("department") or "unknown"
    role       = claims.get("role") or "user"

    ctx = _run_pipeline(prompt, user_id, department, role)
    decision = ctx["decision"]

    # ── Log always (before early return) ─────────────────────────────────────
    _log(
        user_id=str(user_id),
        department=str(department),
        role=str(role),
        prompt=prompt,
        decision=decision,
        pii_detected=ctx["pii_detected"],
        clf_intent=ctx["clf_intent"],
        clf_used_llm=ctx["clf_used_llm"],
        rule_score=ctx["rule_score"],
        sem_score=ctx["sem_score"],
    )

    if decision.decision == "BLOCK":
        return {
            "decision": "BLOCK",
            "risk_score": decision.risk_score,
            "risk_pct": decision.risk_pct,
            "attack_type": decision.attack_type,
            "message": decision.message,
            "contributing_factors": decision.contributing_factors,
        }, 403

    # ── Call LLM with sanitized (PII-redacted) prompt (Streaming) ──────────────
    from services.llm_service import chat_completion_stream
    from flask import Response, stream_with_context
    import json

    def generate():
        # First send the control info (decision, warning, etc)
        control_data = {
            "decision": decision.decision,
            "risk_score": decision.risk_score,
            "risk_pct": decision.risk_pct,
            "attack_type": decision.attack_type,
            "pii_detected": ctx["pii_detected"],
            "warning": decision.message if decision.decision == "WARN" else None,
            "contributing_factors": decision.contributing_factors if decision.decision == "WARN" else None,
        }
        yield f"data: {json.dumps({'type': 'control', 'data': control_data})}\n\n"

        # Now stream the LLM response through the output guard
        from services.output_guard import guard_output_stream
        llm_stream = chat_completion_stream(prompt=ctx["pii_redacted"])
        safe_stream = guard_output_stream(llm_stream)
        
        for chunk in safe_stream:
            yield f"data: {json.dumps({'type': 'chunk', 'text': chunk})}\n\n"
        
        yield "data: [DONE]\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@chat_bp.post("/prompt")
def legacy_prompt():
    """
    Unauthenticated compatibility route.
    POST /api/prompt { message, user_id, department, role }
    """
    body       = request.get_json(silent=True) or {}
    message    = (body.get("message") or "").strip()
    user_id    = body.get("user_id") or "unknown"
    department = body.get("department") or "unknown"
    role       = body.get("role") or "user"

    if not message:
        return {"error": "message required"}, 400

    ctx      = _run_pipeline(message, user_id, department, role)
    decision = ctx["decision"]

    _log(
        user_id=str(user_id),
        department=str(department),
        role=str(role),
        prompt=message,
        decision=decision,
        pii_detected=ctx["pii_detected"],
        clf_intent=ctx["clf_intent"],
        clf_used_llm=ctx["clf_used_llm"],
        rule_score=ctx["rule_score"],
        sem_score=ctx["sem_score"],
    )

    if decision.decision == "BLOCK":
        return {
            "is_blocked": True,
            "reason": decision.message,
            "attack_type": decision.attack_type,
            "risk_score": decision.risk_score,
        }

    llm_text = chat_completion(prompt=ctx["pii_redacted"])
    out = guard_output(llm_text)
    if not out.safe:
        return {
            "is_blocked": True,
            "reason": "Response blocked by output guard.",
            "output_violations": out.violations,
        }

    return {
        "is_blocked": False,
        "response": out.redacted_text,
        "pii_detected": ctx["pii_detected"],
        "warning": decision.message if decision.decision == "WARN" else None,
    }


@chat_bp.get("/logs")
def get_logs():
    try:
        _require_auth()
    except Exception:
        return {"error": "unauthorized"}, 401

    limit = min(max(int(request.args.get("limit", "200")), 1), 1000)
    docs = list(
        _logs_col()
        .find({}, {"prompt": 1, "decision": 1, "risk_score": 1, "attack_type": 1,
                   "timestamp": 1, "department": 1, "user_id": 1, "pii_detected": 1,
                   "clf_intent": 1, "rule_score": 1, "sem_score": 1})
        .sort("timestamp", -1)
        .limit(limit)
    )
    for d in docs:
        d["_id"] = str(d["_id"])
        if "timestamp" in d and hasattr(d["timestamp"], "isoformat"):
            d["timestamp"] = d["timestamp"].isoformat()
    return {"logs": docs}


@chat_bp.get("/analytics/summary")
@limiter.limit("20 per minute")
def analytics_summary():
    try:
        _require_auth()
    except Exception:
        return {"error": "unauthorized"}, 401

    col   = _logs_col()
    total   = col.count_documents({})
    blocked = col.count_documents({"decision": "BLOCK"})
    warned  = col.count_documents({"decision": "WARN"})
    pii_cnt = col.count_documents({"pii_detected": True})

    pipeline_dept = [
        {"$group": {"_id": "$department", "avg_risk": {"$avg": "$risk_score"}, "count": {"$sum": 1}}},
        {"$sort": {"avg_risk": -1}},
        {"$limit": 10},
    ]
    risk_by_dept = [
        {"department": x["_id"], "avg_risk": float(x["avg_risk"]), "count": int(x["count"])}
        for x in col.aggregate(pipeline_dept)
    ]

    pipeline_users = [
        {"$group": {
            "_id": "$user_id",
            "avg_risk": {"$avg": "$risk_score"},
            "blocked": {"$sum": {"$cond": [{"$eq": ["$decision", "BLOCK"]}, 1, 0]}},
            "count": {"$sum": 1},
        }},
        {"$sort": {"avg_risk": -1}},
        {"$limit": 10},
    ]
    top_risky_users = [
        {"user_id": x["_id"], "avg_risk": float(x["avg_risk"]),
         "blocked": int(x["blocked"]), "count": int(x["count"])}
        for x in col.aggregate(pipeline_users)
    ]

    pipeline_attacks = [
        {"$match": {"attack_type": {"$ne": None}}},
        {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    attack_breakdown = [
        {"attack_type": x["_id"], "count": int(x["count"])}
        for x in col.aggregate(pipeline_attacks)
    ]

    return {
        "total_requests": int(total),
        "blocked_attempts": int(blocked),
        "warned_attempts": int(warned),
        "pii_detections": int(pii_cnt),
        "block_rate_pct": round(blocked / total * 100, 1) if total else 0,
        "risk_by_department": risk_by_dept,
        "top_risky_users": top_risky_users,
        "attack_breakdown": attack_breakdown,
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _log(*, user_id, department, role, prompt, decision, pii_detected,
         clf_intent, clf_used_llm, rule_score, sem_score):
    try:
        _logs_col().insert_one({
            "user_id":      user_id,
            "department":   department,
            "role":         role,
            "prompt":       prompt,
            "decision":     decision.decision,
            "risk_score":   decision.risk_score,
            "risk_pct":     decision.risk_pct,
            "attack_type":  decision.attack_type,
            "pii_detected": pii_detected,
            "clf_intent":   clf_intent,
            "clf_used_llm": clf_used_llm,
            "rule_score":   float(rule_score),
            "sem_score":    float(sem_score),
            "factors":      decision.contributing_factors,
            "timestamp":    datetime.datetime.now(datetime.timezone.utc),
        })
    except Exception:
        pass


def _log_output_block(*, user_id, prompt, violations):
    try:
        _logs_col().insert_one({
            "user_id":      user_id,
            "prompt":       prompt,
            "decision":     "BLOCK",
            "attack_type":  "OUTPUT_GUARD",
            "output_violations": violations,
            "timestamp":    datetime.datetime.now(datetime.timezone.utc),
        })
    except Exception:
        pass