from flask import Blueprint, request
from auth.jwt_handler import decode_access_token
from flask import current_app
from database.mongo import get_db

admin_bp = Blueprint("admin", __name__)

def _require_admin():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise PermissionError("missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    claims = decode_access_token(
        token=token,
        secret=current_app.config["JWT_SECRET"],
        issuer=current_app.config["JWT_ISSUER"],
    )
    if claims.get("role") != "admin":
        raise PermissionError("admin only")
    return claims

@admin_bp.get("/rules")
def get_rules():
    try:
        _require_admin()
    except Exception:
        return {"error": "unauthorized"}, 401

    rules = list(get_db()["security_rules"].find({}, {"_id": 0}))
    return {"rules": rules}

@admin_bp.post("/rules")
def add_rule():
    try:
        _require_admin()
    except Exception:
        return {"error": "unauthorized"}, 401
    
    body = request.get_json() or {}
    phrase = body.get("phrase", "").strip().lower()
    attack_type = body.get("attack_type", "CUSTOM_BLOCK")
    if not phrase:
        return {"error": "phrase is required"}, 400

    col = get_db()["security_rules"]
    col.update_one(
        {"phrase": phrase},
        {"$set": {"phrase": phrase, "attack_type": attack_type}},
        upsert=True
    )
    return {"status": "ok", "phrase": phrase}

@admin_bp.delete("/rules/<phrase>")
def delete_rule(phrase):
    try:
        _require_admin()
    except Exception:
        return {"error": "unauthorized"}, 401

    get_db()["security_rules"].delete_many({"phrase": phrase})
    return {"status": "deleted"}
