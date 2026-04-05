from flask import Blueprint, current_app, request

from auth.auth_service import authenticate_user, create_user, issue_token
from database.mongo import get_db_safe


auth_bp = Blueprint("auth", __name__)


def _check_db():
    _, err = get_db_safe()
    if err:
        return {"error": f"Service unavailable: {err}"}, 503
    return None


@auth_bp.post("/signup")
def signup():
    db_err = _check_db()
    if db_err:
        return db_err

    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip()
    password = body.get("password") or ""
    department = body.get("department") or "General"
    role = body.get("role") or "user"

    if not email or not password:
        return {"error": "email and password required"}, 400

    try:
        user_id = create_user(email=email, password=password, department=department, role=role)
    except ValueError as e:
        return {"error": str(e)}, 409
    except Exception as e:
        return {"error": f"Signup failed: {str(e)}"}, 500

    token = issue_token(
        user={"_id": user_id, "email": email, "department": department, "role": role},
        jwt_secret=current_app.config["JWT_SECRET"],
        jwt_issuer=current_app.config["JWT_ISSUER"],
        expires_minutes=current_app.config["JWT_EXPIRES_MINUTES"],
    )
    return {"token": token}


@auth_bp.post("/login")
def login():
    db_err = _check_db()
    if db_err:
        return db_err

    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip()
    password = body.get("password") or ""

    if not email or not password:
        return {"error": "email and password required"}, 400

    try:
        user = authenticate_user(email=email, password=password)
    except Exception as e:
        return {"error": f"Login failed: {str(e)}"}, 500

    if not user:
        return {"error": "invalid credentials"}, 401

    token = issue_token(
        user=user,
        jwt_secret=current_app.config["JWT_SECRET"],
        jwt_issuer=current_app.config["JWT_ISSUER"],
        expires_minutes=current_app.config["JWT_EXPIRES_MINUTES"],
    )
    return {"token": token}
