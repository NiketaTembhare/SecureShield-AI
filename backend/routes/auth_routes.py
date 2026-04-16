from flask import Blueprint, current_app, request, make_response

from auth.auth_service import authenticate_user, create_user, issue_tokens
from auth.jwt_handler import decode_refresh_token, create_access_token
from database.mongo import get_db_safe, get_db
from bson import ObjectId


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
    name = (body.get("name") or "").strip()
    email = (body.get("email") or "").strip()
    password = body.get("password") or ""
    department = body.get("department") or "General"
    role = body.get("role") or "user"

    if not email or not password or not name:
        return {"error": "name, email and password required"}, 400

    try:
        user_id = create_user(name=name, email=email, password=password, department=department, role=role)
    except ValueError as e:
        return {"error": str(e)}, 409
    except Exception as e:
        return {"error": f"Signup failed: {str(e)}"}, 500

    access_token, refresh_token = issue_tokens(
        user={"_id": user_id, "name": name, "email": email, "department": department, "role": role},
        jwt_secret=current_app.config["JWT_SECRET"],
        jwt_issuer=current_app.config["JWT_ISSUER"],
        expires_minutes=current_app.config["JWT_EXPIRES_MINUTES"],
    )
    
    resp = make_response({"token": access_token})
    resp.set_cookie(
        "refresh_token", 
        refresh_token, 
        httponly=True, 
        secure=True, 
        samesite="Strict",
        max_age=7 * 24 * 60 * 60
    )
    return resp

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

    access_token, refresh_token = issue_tokens(
        user=user,
        jwt_secret=current_app.config["JWT_SECRET"],
        jwt_issuer=current_app.config["JWT_ISSUER"],
        expires_minutes=current_app.config["JWT_EXPIRES_MINUTES"],
    )
    
    resp = make_response({"token": access_token})
    resp.set_cookie(
        "refresh_token", 
        refresh_token, 
        httponly=True, 
        secure=True, 
        samesite="Strict",
        max_age=7 * 24 * 60 * 60
    )
    return resp


@auth_bp.post("/refresh")
def refresh():
    token = request.cookies.get("refresh_token")
    if not token:
        return {"error": "missing refresh token"}, 401
        
    try:
        decoded = decode_refresh_token(
            token=token,
            secret=current_app.config["JWT_SECRET"],
            issuer=current_app.config["JWT_ISSUER"]
        )
    except Exception as e:
        return {"error": f"invalid refresh token: {str(e)}"}, 401

    user_id = decoded.get("sub")
    try:
        user = get_db()["users"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        user = None

    if not user:
        return {"error": "user not found"}, 401

    claims = {
        "sub": str(user["_id"]),
        "user_id": str(user["_id"]),
        "email": user.get("email"),
        "department": user.get("department", "unknown"),
        "role": user.get("role", "user"),
    }
    
    access_token = create_access_token(
        secret=current_app.config["JWT_SECRET"],
        issuer=current_app.config["JWT_ISSUER"],
        expires_minutes=current_app.config["JWT_EXPIRES_MINUTES"],
        claims=claims,
    )
    return {"token": access_token}


@auth_bp.post("/logout")
def logout():
    resp = make_response({"status": "logged out"})
    resp.set_cookie("refresh_token", "", httponly=True, secure=True, samesite="Strict", max_age=0)
    return resp
