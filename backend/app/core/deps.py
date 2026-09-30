import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.db import get_db
from app.models import User
from app.service import effective_permission_codes

bearer = HTTPBearer(auto_error=False)
ALLOW_MUST_CHANGE = {"/api/auth/me", "/api/profile/password"}


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> User:
    if creds is None:
        raise HTTPException(status_code=401, detail="未登录")
    try:
        payload = decode_token(creds.credentials)
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="登录已过期") from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="登录已失效") from exc
    user = db.get(User, int(payload.get("uid", 0)))
    if user is None or user.status != 1 or user.token_version != int(payload.get("tv", -1)):
        raise HTTPException(status_code=401, detail="登录已失效")
    if user.must_change_password and request.url.path not in ALLOW_MUST_CHANGE:
        raise HTTPException(status_code=403, detail="请先修改初始密码")
    return user


def require(*codes: str):
    def checker(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
        owned = set(effective_permission_codes(db, user))
        if not any(code in owned for code in codes):
            raise HTTPException(status_code=403, detail="没有权限")
        return user

    return checker
