import datetime
from typing import Any, Dict, Optional

from flask import Blueprint, current_app, request, Response, stream_with_context
import json

from auth.jwt_handler import decode_access_token
from database.mongo import get_db
from services.normalization import normalize_text
from services.rule_engine import primary_attack_type, run_rules, max_rule_score
from services.semantic_engine import semantic_scan
from services.llm_classifier import classify_intent, ClassifierResult
from services.policy_engine import evaluate_policy
from services.pii_detector import detect_and_redact, PiiResult
from services.risk_engine import compute_decision
from services.llm_service import chat_completion, chat_completion_stream
from services.output_guard import guard_output, guard_output_stream
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

def _require_admin_role() -> Dict[str, Any]:
    claims = _require_auth()
    if claims.get("role") != "admin":
        raise PermissionError("admin only")
    return claims


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

    # ── Fast-Path for simple greetings (Latency optimization) ─────────────────
    # Skip heavy ML scans for short, benign greetings to give instant response
    greetings = {"hi", "hii", "hello", "hey", "hola", "namaste", "testing", "test"}
    if len(normalized) < 10 and normalized in greetings:
        # Consistent return structure that matches the full-scan below
        return {
            "normalized": normalized,
            "rule_score": 0.0,
            "attack_type": None,
            "sem_score": 0.0,
            "sem_matched": None,
            "clf_intent": "SAFE",
            "clf_confidence": 1.0,
            "clf_rationale": "Fast-path greeting",
            "clf_used_llm": False,
            "policy_allowed": True,
            "policy_reason": "Greeting fast-path",
            "pii_detected": False,
            "pii_entities": [],
            "pii_redacted": prompt,
            "decision": compute_decision(
                rule_score=0.0,
                semantic_score=0.0,
                intent_score=0.0,
                pii_score=0.0,
                policy_score=0.0,
                policy_allowed=True,
                attack_type=None,
                intent="SAFE",
                pii_detected=False
            ),
        }

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
# @limiter.limit("10 per minute")
def chat():
    """
    Authenticated chat endpoint.
    Flow: Auth → Pipeline → (BLOCK early return) → Stream (Control Chunk → LLM Chunks)
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
    user_name  = claims.get("name") or "Unknown"
    department = claims.get("department") or "unknown"
    role       = claims.get("role") or "user"

    def generate():
        try:
            ctx = _run_pipeline(prompt, user_id, department, role)
            decision = ctx["decision"]

            # Log the request
            _log(
                user_id=str(user_id),
                user_name=str(user_name),
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
                yield f"data: {json.dumps({'type': 'error', 'message': decision.message, 'decision': 'BLOCK'})}\n\n"
                return

            # Yield control chunk with security metadata
            yield f"data: {json.dumps({
                'type': 'control',
                'data': {
                    'decision': decision.decision,
                    'risk_score': decision.risk_score,
                    'risk_pct': decision.risk_pct,
                    'attack_type': decision.attack_type,
                    'pii_detected': ctx['pii_detected'],
                    'warning': decision.message if decision.decision == 'WARN' else None,
                    'contributing_factors': decision.contributing_factors
                }
            })}\n\n"

            # Stream the LLM response through the output guard
            llm_stream = chat_completion_stream(prompt=ctx["pii_redacted"])
            safe_stream = guard_output_stream(llm_stream)
            
            for chunk in safe_stream:
                if chunk:
                    yield f"data: {json.dumps({'type': 'chunk', 'text': chunk})}\n\n"
            
            yield "data: [DONE]\n\n"

        except Exception as e:
            current_app.logger.error(f"Streaming error: {str(e)}")
            yield f"data: {json.dumps({'type': 'error', 'message': 'Internal streaming error'})}\n\n"

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
    user_name  = body.get("name") or "Unknown"
    department = body.get("department") or "unknown"
    role       = body.get("role") or "user"

    if not message:
        return {"error": "message required"}, 400

    ctx      = _run_pipeline(message, user_id, department, role)
    decision = ctx["decision"]

    _log(
        user_id=str(user_id),
        user_name=str(user_name),
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
        _require_admin_role()
    except Exception as e:
        return {"error": str(e) if str(e) == "admin only" else "unauthorized"}, 401

    limit = min(max(int(request.args.get("limit", "200")), 1), 1000)
    docs = list(
        _logs_col()
        .find({}, {"prompt": 1, "decision": 1, "risk_score": 1, "attack_type": 1,
                   "timestamp": 1, "department": 1, "user_id": 1, "pii_detected": 1,
                   "clf_intent": 1, "rule_score": 1, "sem_score": 1, "user": 1, "input": 1, "security_assessment": 1})
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
        _require_admin_role()
    except Exception as e:
        return {"error": str(e) if str(e) == "admin only" else "unauthorized"}, 401

    col   = _logs_col()
    total   = col.count_documents({})
    blocked = col.count_documents({"$or": [{"decision": "BLOCK"}, {"security_assessment.action_taken": "BLOCK"}]})
    warned  = col.count_documents({"$or": [{"decision": "WARN"}, {"security_assessment.action_taken": "WARN"}]})
    pii_cnt = col.count_documents({"$or": [{"pii_detected": True}, {"security_assessment.pii_flagged": True}]})

    pipeline_dept = [
        {"$group": {
            "_id": {"$ifNull": ["$department", "$user.department"]}, 
            "avg_risk": {"$avg": {"$ifNull": ["$risk_score", "$security_assessment.severity_score"]}}, 
            "count": {"$sum": 1}
        }},
        {"$sort": {"avg_risk": -1}},
        {"$limit": 10},
    ]
    risk_by_dept = [
        {"department": x.get("_id") or "Unknown", "avg_risk": float(x.get("avg_risk") or 0.0), "count": int(x.get("count") or 0)}
        for x in col.aggregate(pipeline_dept)
    ]

    pipeline_users = [
        {"$group": {
            "_id": {"$ifNull": ["$user.name", {"$concat": ["User ", {"$substr": [{"$toString": "$user_id"}, 0, 6]}]}]}, 
            "avg_risk": {"$avg": {"$ifNull": ["$risk_score", "$security_assessment.severity_score"]}},
            "blocked": {
                "$sum": {
                    "$cond": [
                        {"$or": [
                            {"$eq": ["$decision", "BLOCK"]}, 
                            {"$eq": ["$security_assessment.action_taken", "BLOCK"]}
                        ]}, 1, 0
                    ]
                }
            },
            "count": {"$sum": 1},
        }},
        {"$sort": {"avg_risk": -1}},
        {"$limit": 10},
    ]
    top_risky_users = [
        # Dashboard expects "user_id" string but we map name here to display as proper name
        {"user_id": x.get("_id") or "Unknown", "avg_risk": float(x.get("avg_risk") or 0.0),
         "blocked": int(x.get("blocked") or 0), "count": int(x.get("count") or 0)}
        for x in col.aggregate(pipeline_users)
    ]

    pipeline_attacks = [
        {"$project": {
            "resolved_attack": {"$ifNull": ["$attack_type", "$security_assessment.attack_type"]}
        }},
        {"$match": {"resolved_attack": {"$ne": None}}},
        {"$group": {"_id": "$resolved_attack", "count": {"$sum": 1}}},
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

def _log(*, user_id, user_name, department, role, prompt, decision, pii_detected,
         clf_intent, clf_used_llm, rule_score, sem_score):
    try:
        preview = prompt[:200] + "..." if len(prompt) > 200 else prompt
        
        _logs_col().insert_one({
            "timestamp": datetime.datetime.now(datetime.timezone.utc),
            "user": {
                "id": user_id,
                "name": user_name,
                "department": department,
                "role": role,
            },
            "input": {
                "prompt_preview": preview
            },
            "security_assessment": {
                "action_taken": decision.decision,
                "severity_score": decision.risk_score,
                "severity_score_pct": decision.risk_pct,
                "attack_type": decision.attack_type,
                "pii_flagged": pii_detected,
                "flags": decision.contributing_factors,
                "clf_intent": clf_intent,
                "rule_score": float(rule_score),
                "sem_score": float(sem_score),
            }
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