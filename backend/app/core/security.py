import hashlib
import re
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from app.core.config import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{4,20}$")
PASSWORD_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{8,32}$")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def validate_username(username: str) -> None:
    if not USERNAME_RE.match(username or ""):
        raise ValueError("用户名需为 4–20 位字母、数字或下划线")


def validate_password(password: str) -> None:
    if not PASSWORD_RE.match(password or ""):
        raise ValueError("密码需为 8–32 位，且同时包含字母和数字")


def create_token(user_id: int, token_version: int) -> str:
    settings = get_settings()
    payload = {
        "uid": user_id,
        "tv": token_version,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_token(token: str) -> dict:
    settings = get_settings()
    return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])


def hash_code(code: str) -> str:
    secret = get_settings().jwt_secret
    return hashlib.sha256(f"{secret}:{code}".encode()).hexdigest()
