import datetime
from typing import Any, Dict

import jwt


def create_access_token(*, secret: str, issuer: str, expires_minutes: int, claims: Dict[str, Any]) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "iss": issuer,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=expires_minutes)).timestamp()),
        "type": "access",
        **claims,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_access_token(*, token: str, secret: str, issuer: str) -> Dict[str, Any]:
    decoded = jwt.decode(token, secret, algorithms=["HS256"], issuer=issuer, options={"require": ["exp", "iat", "iss", "type"]})
    if decoded.get("type") != "access":
        raise jwt.InvalidTokenError("Invalid token type")
    return decoded


def create_refresh_token(*, secret: str, issuer: str, expires_days: int, user_id: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "iss": issuer,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(days=expires_days)).timestamp()),
        "type": "refresh",
        "sub": user_id,
        "user_id": user_id,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_refresh_token(*, token: str, secret: str, issuer: str) -> Dict[str, Any]:
    decoded = jwt.decode(token, secret, algorithms=["HS256"], issuer=issuer, options={"require": ["exp", "iat", "iss", "type", "sub"]})
    if decoded.get("type") != "refresh":
        raise jwt.InvalidTokenError("Invalid token type")
    return decoded

