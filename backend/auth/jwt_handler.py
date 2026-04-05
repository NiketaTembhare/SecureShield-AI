import datetime
from typing import Any, Dict

import jwt


def create_access_token(*, secret: str, issuer: str, expires_minutes: int, claims: Dict[str, Any]) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "iss": issuer,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=expires_minutes)).timestamp()),
        **claims,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_access_token(*, token: str, secret: str, issuer: str) -> Dict[str, Any]:
    return jwt.decode(token, secret, algorithms=["HS256"], issuer=issuer, options={"require": ["exp", "iat", "iss"]})

