from typing import Dict, Optional

import bcrypt

from database.mongo import get_db
from auth.jwt_handler import create_access_token

def _hash_pw(password: str) -> str:
    # bcrypt requires bytes
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def _verify_pw(password: str, hashed_pw: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_pw.encode('utf-8'))
    except ValueError:
        return False


def _users_col():
    return get_db()["users"]


def create_user(*, name: str, email: str, password: str, department: str, role: str) -> str:
    email_norm = email.strip().lower()
    if _users_col().find_one({"email": email_norm}):
        raise ValueError("User already exists")

    doc = {
        "name": name,
        "email": email_norm,
        "password_hash": _hash_pw(password),
        "department": department,
        "role": role,
    }
    res = _users_col().insert_one(doc)
    return str(res.inserted_id)


def authenticate_user(*, email: str, password: str) -> Optional[Dict]:
    email_norm = email.strip().lower()
    user = _users_col().find_one({"email": email_norm})
    if not user:
        return None
    if not _verify_pw(password, user.get("password_hash", "")):
        return None
    return user


from auth.jwt_handler import create_access_token, create_refresh_token
from typing import Dict, Optional, Tuple

# ... existing code ...

def issue_tokens(*, user: Dict, jwt_secret: str, jwt_issuer: str, expires_minutes: int) -> Tuple[str, str]:
    claims = {
        "sub": str(user["_id"]),
        "user_id": str(user["_id"]),
        "name": user.get("name", "Unknown"),
        "email": user.get("email"),
        "department": user.get("department", "unknown"),
        "role": user.get("role", "user"),
    }
    
    access_token = create_access_token(
        secret=jwt_secret,
        issuer=jwt_issuer,
        expires_minutes=expires_minutes,
        claims=claims,
    )
    
    refresh_token = create_refresh_token(
        secret=jwt_secret,
        issuer=jwt_issuer,
        expires_days=7, # 7 days refresh 
        user_id=str(user["_id"])
    )
    
    return access_token, refresh_token

