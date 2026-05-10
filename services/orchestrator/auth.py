from datetime import datetime, timezone, timedelta
from typing import Any
from uuid import uuid4

from jose import JWTError, jwt

ALGORITHM = "HS256"
ISSUER = "norda-mas"


class AuthError(Exception):
    pass


def sign_message(payload: dict[str, Any], secret: str, ttl_seconds: int = 30) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        **payload,
        "iss": ISSUER,
        "iat": now,
        "exp": now + timedelta(seconds=ttl_seconds),
        "jti": str(uuid4()),
    }
    try:
        return jwt.encode(claims, secret, algorithm=ALGORITHM)
    except Exception as e:
        raise AuthError(f"Failed to sign message: {e}") from e


def verify_message(token: str, secret: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, secret, algorithms=[ALGORITHM], issuer=ISSUER)
    except JWTError as e:
        raise AuthError(f"Invalid token: {e}") from e
