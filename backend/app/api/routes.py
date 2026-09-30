import csv
import io
import re
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import get_current_user, require
from app.core.security import (
    create_token,
    hash_code,
    hash_password,
    validate_password,
    validate_username,
    verify_password,
)
from app.db import get_db
from app.jobs import (
    cancel_file,
    clear_model_cache,
    infer_mail,
    load_published,
    save_detection,
    tail_file,
)
from app.kg.extract import extract_mail
from app.kg.store import REL_RULES, SqlGraphStore, get_graph
from app.mailio import MAX_DATASET, MAX_DETECT, MailParseError, parse_upload
from app.models import (
    CertSnapshot,
    Dataset,
    DetectEvidence,
    DetectRecord,
    DetectTask,
    EmailVerifyCode,
    ExtractedTriple,
    KgAudit,
    MailSample,
    ModelVersion,
    Permission,
    Role,
    RolePermission,
    TrainTask,
    User,
    UserRole,
)
from app.seed import DEMO_CERTS, sample_rows
from app.service import (
    audit,
    commit_triple_rows,
    content_hash,
    effective_permission_codes,
    enabled_admin_count,
    is_admin,
    refresh_counts,
    role_chain,
    store_triples,
    user_role_codes,
    write_extraction,
)

router = APIRouter()


class RegisterIn(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str


class LoginIn(BaseModel):
    account: str
    password: str


class ForgotIn(BaseModel):
    account: str


class ResetIn(BaseModel):
    account: str
    code: str
    password: str


class ProfileIn(BaseModel):
    nickname: str = Field(min_length=1, max_length=40)
    email: EmailStr
    phone: str = ""


class PasswordIn(BaseModel):
    old_password: str
    new_password: str


class UserWrite(BaseModel):
    username: str | None = None
    email: EmailStr | None = None
    nickname: str | None = None
    phone: str = ""
    password: str | None = None
    status: int | None = None
    role_codes: list[str] | None = None


class RoleWrite(BaseModel):
    code: str | None = None
    name: str
    parent_role_id: int | None = None
    remark: str = ""


class PermWrite(BaseModel):
    codes: list[str]


class TrainIn(BaseModel):
    dataset_id: int
    epoch: int = 40
    batch_size: int = 32
    lr: float = 0.001
    weight_decay: float = 0.0001
    dropout: float = 0.3
    seed: int = 42
    early_stop: bool = True


class LabelIn(BaseModel):
    label: str


class FeedbackIn(BaseModel):
    feedback: str


class NodeIn(BaseModel):
    id: str | None = None
    name: str | None = None
    remark: str | None = None
    locked: bool | None = None
    manual_risk: str | None = None


class RelationIn(BaseModel):
    rel: str
    source: str
    target: str


class MergeIn(BaseModel):
    keep_id: str
    drop_id: str


class TripleIds(BaseModel):
    triple_ids: list[int]


def dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.strftime("%Y-%m-%d %H:%M:%S")


def check_phone(phone: str) -> None:
    if phone and not re.fullmatch(r"[0-9+\-]{6,20}", phone):
        raise HTTPException(status_code=400, detail="联系方式格式不正确")


def public_user(db: Session, user: User, with_perms: bool = False) -> dict:
    data = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "phone": user.phone or "",
        "nickname": user.nickname,
        "avatar_url": f"/media/avatar/{Path(user.avatar_path).name}" if user.avatar_path else "",
        "status": user.status,
        "roles": list(user_role_codes(db, user.id)),
        "must_change_password": bool(user.must_change_password),
        "created_at": dt(user.created_at),
        "last_login_at": dt(user.last_login_at),
    }
    if with_perms:
        data["permissions"] = effective_permission_codes(db, user)
    return data


def find_account(db: Session, account: str) -> User | None:
    return db.scalar(select(User).where(or_(User.username == account, User.email == account)))


def set_roles(db: Session, user: User, codes: list[str]) -> None:
    roles = db.scalars(select(Role).where(Role.code.in_(codes))).all() if codes else []
    if len(roles) != len(set(codes)):
        raise HTTPException(status_code=400, detail="存在未知角色")
    admin = db.scalar(select(Role).where(Role.code == "ADMIN"))
    had_admin = None
    if admin is not None:
        had_admin = db.scalar(select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == admin.id))
    will_admin = any(role.code == "ADMIN" for role in roles)
    if had_admin and not will_admin and user.status == 1 and enabled_admin_count(db) <= 1:
        raise HTTPException(status_code=409, detail="不能取消最后一个管理员的角色")
    db.query(UserRole).filter(UserRole.user_id == user.id).delete()
    for role in roles:
        db.add(UserRole(user_id=user.id, role_id=role.id))


def ensure_parent_ok(db: Session, role: Role, parent_id: int | None) -> None:
    if parent_id == role.id:
        raise HTTPException(status_code=400, detail="角色不能继承自己")
    if parent_id:
        chain = role_chain(db, parent_id)
        if any(item.id == role.id for item in chain):
            raise HTTPException(status_code=400, detail="角色继承形成了环")
        if len(chain) >= 3:
            raise HTTPException(status_code=400, detail="角色继承不能超过 3 层")
    children = db.scalars(select(Role).where(Role.parent_role_id == role.id)).all()
    for child in children:
        if parent_id and len(role_chain(db, parent_id)) + 1 >= 3:
            raise HTTPException(status_code=400, detail="调整后子角色的继承深度会超过 3 层")


def page_args(page: int, size: int) -> tuple[int, int]:
    return max(page, 1), min(max(size, 1), 100)


def add_mails(db: Session, dataset: Dataset, rows: list[dict]) -> None:
    cert_map = {item.domain: item.issuer for item in db.scalars(select(CertSnapshot)).all()}
    logos = get_graph(db).known_logos()
    for row in rows:
        sample = MailSample(
            dataset_id=dataset.id,
            subject=(row.get("subject") or "")[:500],
            body=(row.get("body") or "")[:500000],
            from_addr=row.get("from_addr"),
            label=row.get("label"),
            content_hash=content_hash(row.get("subject") or "", row.get("body") or ""),
            created_at=datetime.now(),
        )
        db.add(sample)
        db.flush()
        extracted = extract_mail(
            sample_key=str(sample.id),
            subject=sample.subject,
            body=sample.body,
            from_addr=sample.from_addr,
            html=row.get("html") or "",
            images=row.get("images") or [],
            cert_map=cert_map,
            known_logos=logos,
        )
        store_triples(db, dataset.id, sample, extracted)
    refresh_counts(db, dataset)


def dataset_dict(item: Dataset) -> dict:
    return {
        "id": item.id,
        "name": item.name,
        "parent_id": item.parent_id,
        "status": item.status,
        "sample_count": item.sample_count,
        "phish_count": item.phish_count,
        "ham_count": item.ham_count,
        "created_at": dt(item.created_at),
    }


def model_dict(db: Session, item: ModelVersion) -> dict:
    dataset = db.get(Dataset, item.dataset_id)
    return {
        "id": item.id,
        "task_id": item.task_id,
        "version_no": item.version_no,
        "dataset_id": item.dataset_id,
        "dataset_name": dataset.name if dataset else "",
        "published": bool(item.published),
        "sample_count": item.sample_count,
        "created_at": dt(item.created_at),
        "config": item.config_json,
        "metrics": item.metrics_json,
    }


def record_dict(db: Session, item: DetectRecord) -> dict:
    version = db.get(ModelVersion, item.model_id)
    evidences = db.scalars(select(DetectEvidence).where(DetectEvidence.record_id == item.id)).all()
    return {
        "id": item.id,
        "task_id": item.task_id,
        "subject": item.subject,
        "pred_label": item.pred_label,
        "confidence": float(item.confidence),
        "p_gnn": float(item.p_gnn),
        "p_rule": float(item.p_rule),
        "p_final": float(item.p_final),
        "feedback": item.feedback,
        "summary": item.summary_json or [],
        "model_version": version.version_no if version else "",
        "model_id": item.model_id,
        "created_at": dt(item.created_at),
        "evidences": [
            {"path_text": ev.path_text, "risk_score": float(ev.risk_score), "entity_type": ev.entity_type}
            for ev in evidences
        ],
    }


def owned_record(db: Session, user: User, record_id: int) -> DetectRecord:
    record = db.get(DetectRecord, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="识别记录不存在")
    if record.user_id != user.id and not is_admin(db, user):
        raise HTTPException(status_code=403, detail="没有权限")
    return record


def check_train_config(body: TrainIn) -> dict:
    ranges = {
        "epoch": (body.epoch, 5, 100),
        "batch_size": (body.batch_size, 8, 128),
        "lr": (body.lr, 0.0001, 0.01),
        "weight_decay": (body.weight_decay, 0, 0.001),
        "dropout": (body.dropout, 0, 0.5),
    }
    for name, (value, low, high) in ranges.items():
        if not low <= value <= high:
            raise HTTPException(status_code=400, detail=f"{name} 超出允许范围")
    return {
        "epoch": body.epoch,
        "batch_size": body.batch_size,
        "lr": body.lr,
        "weight_decay": body.weight_decay,
        "dropout": body.dropout,
        "seed": body.seed,
        "early_stop": body.early_stop,
        "patience": 8,
    }


def graph_call(action):
    try:
        return action()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="节点或关系不存在") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/health")
def health():
    return {"status": "ok"}


@router.post("/auth/register")
def register(body: RegisterIn, db: Session = Depends(get_db)):
    try:
        validate_username(body.username)
        validate_password(body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if body.password != body.confirm_password:
        raise HTTPException(status_code=400, detail="两次输入的密码不一致")
    if find_account(db, body.username) or db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(status_code=409, detail="用户名或邮箱已存在")
    user = User(
        username=body.username,
        email=str(body.email),
        password_hash=hash_password(body.password),
        nickname=body.username,
        status=1,
        created_at=datetime.now(),
    )
    db.add(user)
    db.flush()
    role = db.scalar(select(Role).where(Role.code == "USER"))
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.commit()
    return public_user(db, user)


@router.post("/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = find_account(db, body.account.strip())
    if user is None:
        raise HTTPException(status_code=401, detail="账号或密码错误")
    if user.status != 1:
        raise HTTPException(status_code=403, detail="账号已禁用")
    if user.locked_until and user.locked_until > datetime.now():
        raise HTTPException(status_code=403, detail="账号已锁定，请稍后再试")
    if not verify_password(body.password, user.password_hash):
        user.fail_count += 1
        if user.fail_count >= 5:
            user.locked_until = datetime.now() + timedelta(minutes=15)
            user.fail_count = 0
        db.commit()
        raise HTTPException(status_code=401, detail="账号或密码错误")
    user.fail_count = 0
    user.locked_until = None
    user.last_login_at = datetime.now()
    db.commit()
    return {"token": create_token(user.id, user.token_version), "user": public_user(db, user, with_perms=True)}


@router.post("/auth/forgot")
def forgot(body: ForgotIn, db: Session = Depends(get_db)):
    user = find_account(db, body.account.strip())
    message = "如果账号存在，验证码已发送"
    if user is None:
        return {"message": message}
    code = f"{secrets_code()}"
    db.add(EmailVerifyCode(
        user_id=user.id,
        purpose="RESET_PASSWORD",
        code_hash=hash_code(code),
        expire_at=datetime.now() + timedelta(minutes=10),
        attempts=0,
        used=0,
    ))
    db.commit()
    _deliver_code(user, code)
    return {"message": message}


def secrets_code() -> str:
    import secrets
    return f"{secrets.randbelow(1000000):06d}"


def _deliver_code(user: User, code: str) -> None:
    import logging
    import smtplib
    from email.message import EmailMessage

    settings = get_settings()
    logger = logging.getLogger("phishkg.mail")
    text = f"用户 {user.username} 的密码重置验证码：{code}，10 分钟内有效。"
    if not settings.mail_enabled:
        logger.warning(text)
        path = settings.data_path / "logs" / "mail.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {text}\n")
        return
    if not settings.smtp_host:
        raise HTTPException(status_code=500, detail="邮件服务未配置")
    msg = EmailMessage()
    msg["Subject"] = "密码重置验证码"
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = user.email
    msg.set_content(text)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as client:
        client.starttls()
        if settings.smtp_user:
            client.login(settings.smtp_user, settings.smtp_password)
        client.send_message(msg)


@router.post("/auth/reset")
def reset_password(body: ResetIn, db: Session = Depends(get_db)):
    try:
        validate_password(body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    user = find_account(db, body.account.strip())
    if user is None:
        raise HTTPException(status_code=400, detail="验证码错误")
    row = db.scalar(
        select(EmailVerifyCode)
        .where(EmailVerifyCode.user_id == user.id, EmailVerifyCode.purpose == "RESET_PASSWORD", EmailVerifyCode.used == 0)
        .order_by(EmailVerifyCode.id.desc())
    )
    if row is None or row.attempts >= 5:
        raise HTTPException(status_code=400, detail="验证码已失效")
    if row.expire_at < datetime.now():
        raise HTTPException(status_code=400, detail="验证码已过期")
    if hash_code(body.code.strip()) != row.code_hash:
        row.attempts += 1
        db.commit()
        if row.attempts >= 5:
            raise HTTPException(status_code=400, detail="验证码错误次数过多")
        raise HTTPException(status_code=400, detail="验证码错误")
    if verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=400, detail="新密码不能与原密码相同")
    row.used = 1
    user.password_hash = hash_password(body.password)
    user.token_version += 1
    user.must_change_password = 0
    user.fail_count = 0
    user.locked_until = None
    db.commit()
    return {"message": "密码已重置，请重新登录"}


@router.get("/auth/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return public_user(db, user, with_perms=True)


@router.put("/profile")
def update_profile(body: ProfileIn, user: User = Depends(require("profile:update")), db: Session = Depends(get_db)):
    check_phone(body.phone)
    existed = db.scalar(select(User).where(User.email == str(body.email), User.id != user.id))
    if existed:
        raise HTTPException(status_code=409, detail="邮箱已被占用")
    user.nickname = body.nickname
    user.email = str(body.email)
    user.phone = body.phone or None
    db.commit()
    return public_user(db, user, with_perms=True)


@router.put("/profile/password")
def change_password(body: PasswordIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(body.old_password, user.password_hash):
        raise HTTPException(status_code=400, detail="原密码不正确")
    if body.old_password == body.new_password:
        raise HTTPException(status_code=400, detail="新密码不能与原密码相同")
    try:
        validate_password(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1
    user.must_change_password = 0
    db.commit()
    return {"token": create_token(user.id, user.token_version)}


@router.post("/profile/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    user: User = Depends(require("profile:update")),
    db: Session = Depends(get_db),
):
    from io import BytesIO
    from PIL import Image, UnidentifiedImageError

    raw = await file.read()
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="头像不能超过 2 MB")
    try:
        image = Image.open(BytesIO(raw))
        image.load()
    except UnidentifiedImageError as exc:
        raise HTTPException(status_code=400, detail="头像仅支持 jpg、png、webp") from exc
    fmt = (image.format or "").upper()
    if fmt not in {"JPEG", "PNG", "WEBP"}:
        raise HTTPException(status_code=400, detail="头像仅支持 jpg、png、webp")
    ext = {"JPEG": "jpg", "PNG": "png", "WEBP": "webp"}[fmt]
    folder = get_settings().data_path / "avatar"
    folder.mkdir(parents=True, exist_ok=True)
    for old in folder.glob(f"{user.id}.*"):
        old.unlink(missing_ok=True)
    if fmt == "JPEG" and image.mode not in {"RGB", "L"}:
        image = image.convert("RGB")
    image.save(folder / f"{user.id}.{ext}")
    user.avatar_path = f"avatar/{user.id}.{ext}"
    db.commit()
    return public_user(db, user, with_perms=True)


@router.get("/admin/users")
def list_users(
    keyword: str = "",
    role: str = "",
    status: int | None = None,
    page: int = 1,
    size: int = 10,
    _: User = Depends(require("user:manage")),
    db: Session = Depends(get_db),
):
    page, size = page_args(page, size)
    stmt = select(User)
    if keyword:
        stmt = stmt.where(or_(User.username.contains(keyword), User.email.contains(keyword)))
    if status is not None:
        stmt = stmt.where(User.status == status)
    users = db.scalars(stmt.order_by(User.id.desc())).all()
    if role:
        users = [user for user in users if role in user_role_codes(db, user.id)]
    total = len(users)
    items = [public_user(db, user) for user in users[(page - 1) * size: page * size]]
    return {"items": items, "total": total, "page": page, "size": size}


@router.post("/admin/users")
def create_user(body: UserWrite, _: User = Depends(require("user:manage")), db: Session = Depends(get_db)):
    try:
        validate_username(body.username or "")
        validate_password(body.password or "")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    check_phone(body.phone)
    if db.scalar(select(User).where(or_(User.username == body.username, User.email == str(body.email)))):
        raise HTTPException(status_code=409, detail="用户名或邮箱已存在")
    user = User(
        username=body.username,
        email=str(body.email),
        password_hash=hash_password(body.password or ""),
        nickname=body.nickname or body.username,
        phone=body.phone or None,
        status=1 if body.status is None else body.status,
        must_change_password=1,
        created_at=datetime.now(),
    )
    db.add(user)
    db.flush()
    set_roles(db, user, body.role_codes or ["USER"])
    db.commit()
    return public_user(db, user)


@router.put("/admin/users/{user_id}")
def update_user(user_id: int, body: UserWrite, operator: User = Depends(require("user:manage")), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    if body.email:
        existed = db.scalar(select(User).where(User.email == str(body.email), User.id != user.id))
        if existed:
            raise HTTPException(status_code=409, detail="邮箱已被占用")
        user.email = str(body.email)
    if body.nickname:
        user.nickname = body.nickname
    if body.phone is not None:
        check_phone(body.phone)
        user.phone = body.phone or None
    if body.status is not None:
        if body.status == 0 and user.id == operator.id:
            raise HTTPException(status_code=409, detail="不能禁用自己")
        if body.status == 0 and "ADMIN" in user_role_codes(db, user.id) and enabled_admin_count(db) <= 1:
            raise HTTPException(status_code=409, detail="不能禁用最后一个管理员")
        user.status = body.status
        if body.status == 0:
            user.token_version += 1
    if body.password:
        try:
            validate_password(body.password)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        user.password_hash = hash_password(body.password)
        user.must_change_password = 1
        user.token_version += 1
    if body.role_codes is not None:
        set_roles(db, user, body.role_codes)
    db.commit()
    return public_user(db, user)


@router.delete("/admin/users/{user_id}")
def delete_user(user_id: int, operator: User = Depends(require("user:manage")), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    if user.id == operator.id:
        raise HTTPException(status_code=400, detail="不能删除自己")
    if "ADMIN" in user_role_codes(db, user.id) and user.status == 1 and enabled_admin_count(db) <= 1:
        raise HTTPException(status_code=409, detail="不能删除最后一个管理员")
    used = db.scalar(select(func.count()).select_from(DetectRecord).where(DetectRecord.user_id == user.id))
    created = db.scalar(select(func.count()).select_from(Dataset).where(Dataset.created_by == user.id))
    if used or created:
        raise HTTPException(status_code=409, detail="该用户已有业务数据，请改为禁用")
    db.query(UserRole).filter(UserRole.user_id == user.id).delete()
    db.delete(user)
    db.commit()
    return {"ok": True}


@router.put("/admin/users/{user_id}/roles")
def assign_roles(user_id: int, body: PermWrite, _: User = Depends(require("user:manage")), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    set_roles(db, user, body.codes)
    db.commit()
    return public_user(db, user)


@router.get("/admin/permissions")
def list_permissions(_: User = Depends(require("role:manage")), db: Session = Depends(get_db)):
    rows = db.scalars(select(Permission).order_by(Permission.id)).all()
    return [{"code": row.code, "name": row.name} for row in rows]


@router.get("/admin/roles")
def list_roles(_: User = Depends(require("role:manage")), db: Session = Depends(get_db)):
    roles = db.scalars(select(Role).order_by(Role.id)).all()
    result = []
    for role in roles:
        perm_ids = db.scalars(select(RolePermission.permission_id).where(RolePermission.role_id == role.id)).all()
        codes = db.scalars(select(Permission.code).where(Permission.id.in_(perm_ids or [0]))).all() if perm_ids else []
        result.append({
            "id": role.id,
            "code": role.code,
            "name": role.name,
            "parent_role_id": role.parent_role_id,
            "builtin": bool(role.builtin),
            "remark": role.remark or "",
            "permissions": list(codes),
        })
    return result


@router.post("/admin/roles")
def create_role(body: RoleWrite, _: User = Depends(require("role:manage")), db: Session = Depends(get_db)):
    if not body.code or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,31}", body.code):
        raise HTTPException(status_code=400, detail="角色编码需为大写字母、数字或下划线")
    if db.scalar(select(Role).where(Role.code == body.code)):
        raise HTTPException(status_code=409, detail="角色编码已存在")
    role = Role(code=body.code, name=body.name, builtin=0, remark=body.remark, parent_role_id=body.parent_role_id)
    db.add(role)
    db.flush()
    ensure_parent_ok(db, role, body.parent_role_id)
    db.commit()
    return {"id": role.id}


@router.put("/admin/roles/{role_id}")
def update_role(role_id: int, body: RoleWrite, _: User = Depends(require("role:manage")), db: Session = Depends(get_db)):
    role = db.get(Role, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="角色不存在")
    if body.code and body.code != role.code:
        raise HTTPException(status_code=400, detail="不允许修改角色编码")
    ensure_parent_ok(db, role, body.parent_role_id)
    role.name = body.name
    role.parent_role_id = body.parent_role_id
    role.remark = body.remark
    db.commit()
    return {"ok": True}


@router.put("/admin/roles/{role_id}/permissions")
def update_role_perms(role_id: int, body: PermWrite, _: User = Depends(require("role:manage")), db: Session = Depends(get_db)):
    role = db.get(Role, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="角色不存在")
    perms = db.scalars(select(Permission).where(Permission.code.in_(body.codes))).all() if body.codes else []
    if len(perms) != len(set(body.codes)):
        raise HTTPException(status_code=400, detail="存在未知权限")
    db.query(RolePermission).filter(RolePermission.role_id == role.id).delete()
    for perm in perms:
        db.add(RolePermission(role_id=role.id, permission_id=perm.id))
    db.commit()
    return {"ok": True}


@router.delete("/admin/roles/{role_id}")
def delete_role(role_id: int, _: User = Depends(require("role:manage")), db: Session = Depends(get_db)):
    role = db.get(Role, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="角色不存在")
    if role.builtin:
        raise HTTPException(status_code=400, detail="内置角色不能删除")
    used = db.scalar(select(func.count()).select_from(UserRole).where(UserRole.role_id == role.id))
    if used:
        raise HTTPException(status_code=409, detail="仍有用户使用该角色")
    db.query(RolePermission).filter(RolePermission.role_id == role.id).delete()
    db.delete(role)
    db.commit()
    return {"ok": True}


@router.get("/datasets")
def list_datasets(_: User = Depends(require("dataset:manage")), db: Session = Depends(get_db)):
    rows = db.scalars(select(Dataset).where(Dataset.status != "DELETED").order_by(Dataset.id.desc())).all()
    return [dataset_dict(row) for row in rows]


@router.post("/datasets/sample")
def import_sample(user: User = Depends(require("dataset:manage")), db: Session = Depends(get_db)):
    for domain, issuer in DEMO_CERTS:
        if db.scalar(select(CertSnapshot).where(CertSnapshot.domain == domain)) is None:
            db.add(CertSnapshot(domain=domain, issuer=issuer))
    dataset = Dataset(name="内置示例数据集", status="READY", created_by=user.id, created_at=datetime.now())
    db.add(dataset)
    db.flush()
    add_mails(db, dataset, sample_rows())
    db.commit()
    return dataset_dict(dataset)


@router.post("/datasets")
async def upload_dataset(
    name: str = Form(...),
    label: str | None = Form(None),
    file: UploadFile = File(...),
    user: User = Depends(require("dataset:manage")),
    db: Session = Depends(get_db),
):
    raw = await file.read()
    try:
        rows, warnings = parse_upload(
            file.filename or "",
            raw,
            require_label=True,
            batch_limit=MAX_DATASET,
            default_label=(label or "").lower() or None,
        )
    except MailParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    dataset = Dataset(name=name[:80], status="READY", created_by=user.id, created_at=datetime.now())
    db.add(dataset)
    db.flush()
    add_mails(db, dataset, rows)
    db.commit()
    return {"dataset": dataset_dict(dataset), "warnings": warnings}


@router.post("/datasets/cert-snapshot")
async def upload_certs(
    file: UploadFile = File(...),
    _: User = Depends(require("dataset:manage")),
    db: Session = Depends(get_db),
):
    text = (await file.read()).decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    fields = {name.strip().lower(): name for name in (reader.fieldnames or [])}
    if "domain" not in fields or "issuer" not in fields:
        raise HTTPException(status_code=400, detail="证书快照需要 domain 和 issuer 列")
    count = 0
    for row in reader:
        domain = (row.get(fields["domain"]) or "").strip().lower()
        issuer = (row.get(fields["issuer"]) or "").strip()
        if not domain or not issuer:
            continue
        item = db.scalar(select(CertSnapshot).where(CertSnapshot.domain == domain))
        not_after = (row.get(fields["not_after"]) or "").strip() if "not_after" in fields else ""
        if item is None:
            db.add(CertSnapshot(domain=domain, issuer=issuer, not_after=not_after or None))
        else:
            item.issuer = issuer
            item.not_after = not_after or item.not_after
        count += 1
    db.commit()
    return {"count": count}


@router.get("/datasets/{dataset_id}/samples")
def list_samples(
    dataset_id: int,
    page: int = 1,
    size: int = 10,
    _: User = Depends(require("dataset:manage")),
    db: Session = Depends(get_db),
):
    page, size = page_args(page, size)
    stmt = select(MailSample).where(MailSample.dataset_id == dataset_id).order_by(MailSample.id.desc())
    rows = db.scalars(stmt).all()
    items = [{
        "id": row.id,
        "subject": row.subject,
        "from_addr": row.from_addr,
        "label": row.label,
        "split": row.split,
        "created_at": dt(row.created_at),
    } for row in rows[(page - 1) * size: page * size]]
    return {"items": items, "total": len(rows), "page": page, "size": size}


@router.get("/datasets/{dataset_id}/samples/{sample_id}")
def sample_detail(dataset_id: int, sample_id: int, _: User = Depends(require("dataset:manage")), db: Session = Depends(get_db)):
    sample = db.get(MailSample, sample_id)
    if sample is None or sample.dataset_id != dataset_id:
        raise HTTPException(status_code=404, detail="样本不存在")
    triples = db.scalars(select(ExtractedTriple).where(ExtractedTriple.sample_id == sample.id)).all()
    return {
        "id": sample.id,
        "subject": sample.subject,
        "body": sample.body,
        "from_addr": sample.from_addr,
        "label": sample.label,
        "split": sample.split,
        "triples": [{
            "id": item.id,
            "head": item.head_name,
            "head_type": item.head_type,
            "rel": item.rel,
            "tail": item.tail_name,
            "tail_type": item.tail_type,
            "status": item.status,
        } for item in triples],
    }


@router.put("/datasets/{dataset_id}/samples/{sample_id}")
def update_sample(dataset_id: int, sample_id: int, body: LabelIn, _: User = Depends(require("dataset:manage")), db: Session = Depends(get_db)):
    if body.label not in {"phish", "ham"}:
        raise HTTPException(status_code=400, detail="标签只能是 phish 或 ham")
    sample = db.get(MailSample, sample_id)
    dataset = db.get(Dataset, dataset_id)
    if sample is None or dataset is None or sample.dataset_id != dataset_id:
        raise HTTPException(status_code=404, detail="样本不存在")
    sample.label = body.label
    sample.split = None
    refresh_counts(db, dataset)
    db.commit()
    return {"ok": True}


@router.delete("/datasets/{dataset_id}/samples/{sample_id}")
def delete_sample(dataset_id: int, sample_id: int, _: User = Depends(require("dataset:manage")), db: Session = Depends(get_db)):
    sample = db.get(MailSample, sample_id)
    dataset = db.get(Dataset, dataset_id)
    if sample is None or dataset is None or sample.dataset_id != dataset_id:
        raise HTTPException(status_code=404, detail="样本不存在")
    db.query(ExtractedTriple).filter(ExtractedTriple.sample_id == sample.id).delete()
    db.delete(sample)
    refresh_counts(db, dataset)
    db.commit()
    return {"ok": True}


@router.post("/datasets/{dataset_id}/triples/commit")
def commit_triples(dataset_id: int, body: TripleIds, _: User = Depends(require("dataset:manage")), db: Session = Depends(get_db)):
    rows = _load_triples(db, dataset_id, body.triple_ids)
    grouped: dict[int, list[ExtractedTriple]] = {}
    for row in rows:
        grouped.setdefault(row.sample_id, []).append(row)
    for sample_id, items in grouped.items():
        sample = db.get(MailSample, sample_id)
        commit_triple_rows(db, items, count_label=sample.label if sample else None, sample_key=f"review:{sample_id}")
    db.commit()
    return {"count": len(rows)}


@router.post("/datasets/{dataset_id}/triples/drop")
def drop_triples(dataset_id: int, body: TripleIds, _: User = Depends(require("dataset:manage")), db: Session = Depends(get_db)):
    rows = _load_triples(db, dataset_id, body.triple_ids)
    for row in rows:
        row.status = "dropped"
    db.commit()
    return {"count": len(rows)}


def _load_triples(db: Session, dataset_id: int, ids: list[int]) -> list[ExtractedTriple]:
    if not ids:
        raise HTTPException(status_code=400, detail="请选择三元组")
    rows = db.scalars(select(ExtractedTriple).where(ExtractedTriple.dataset_id == dataset_id, ExtractedTriple.id.in_(ids))).all()
    if len(rows) != len(set(ids)):
        raise HTTPException(status_code=404, detail="有三元组不属于该数据集")
    return list(rows)


@router.post("/datasets/{dataset_id}/clean")
def clean_dataset(dataset_id: int, user: User = Depends(require("dataset:manage")), db: Session = Depends(get_db)):
    source = db.get(Dataset, dataset_id)
    if source is None or source.status == "DELETED":
        raise HTTPException(status_code=404, detail="数据集不存在")
    rows = db.scalars(select(MailSample).where(MailSample.dataset_id == source.id).order_by(MailSample.id)).all()
    seen = set()
    kept = []
    for row in rows:
        body = (row.body or "").strip()
        if len(body) < 10:
            continue
        if row.content_hash in seen:
            continue
        seen.add(row.content_hash)
        kept.append(row)
    dataset = Dataset(name=f"{source.name}-清洗", parent_id=source.id, status="READY", created_by=user.id, created_at=datetime.now())
    db.add(dataset)
    db.flush()
    add_mails(db, dataset, [{
        "subject": row.subject,
        "body": row.body,
        "from_addr": row.from_addr,
        "label": row.label,
    } for row in kept])
    db.commit()
    return dataset_dict(dataset)


@router.delete("/datasets/{dataset_id}")
def delete_dataset(dataset_id: int, _: User = Depends(require("dataset:manage")), db: Session = Depends(get_db)):
    dataset = db.get(Dataset, dataset_id)
    if dataset is None:
        raise HTTPException(status_code=404, detail="数据集不存在")
    referenced = db.scalar(select(func.count()).select_from(TrainTask).where(TrainTask.dataset_id == dataset.id))
    if referenced:
        dataset.status = "DELETED"
        db.commit()
        return {"mode": "logical"}
    sample_ids = db.scalars(select(MailSample.id).where(MailSample.dataset_id == dataset.id)).all()
    if sample_ids:
        db.query(ExtractedTriple).filter(ExtractedTriple.dataset_id == dataset.id).delete()
        db.query(MailSample).filter(MailSample.dataset_id == dataset.id).delete()
    db.delete(dataset)
    db.commit()
    return {"mode": "physical"}


@router.post("/train/tasks")
def create_train(body: TrainIn, user: User = Depends(require("model:train")), db: Session = Depends(get_db)):
    dataset = db.get(Dataset, body.dataset_id)
    if dataset is None or dataset.status != "READY":
        raise HTTPException(status_code=400, detail="数据集不可用于训练")
    config = check_train_config(body)
    log_path = get_settings().data_path / "logs" / f"train-{datetime.now():%Y%m%d%H%M%S}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("", encoding="utf-8")
    task = TrainTask(
        dataset_id=dataset.id,
        status="PENDING",
        config_json=config,
        log_path=str(log_path),
        progress=0,
        created_by=user.id,
        created_at=datetime.now(),
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return {"id": task.id, "status": task.status}


@router.get("/train/tasks")
def list_trains(_: User = Depends(require("model:train")), db: Session = Depends(get_db)):
    rows = db.scalars(select(TrainTask).order_by(TrainTask.id.desc())).all()
    result = []
    for row in rows:
        dataset = db.get(Dataset, row.dataset_id)
        result.append({
            "id": row.id,
            "dataset_id": row.dataset_id,
            "dataset_name": dataset.name if dataset else "",
            "status": row.status,
            "progress": row.progress,
            "error_message": row.error_message,
            "created_at": dt(row.created_at),
            "started_at": dt(row.started_at),
            "finished_at": dt(row.finished_at),
        })
    return result


@router.get("/train/tasks/{task_id}")
def train_detail(task_id: int, _: User = Depends(require("model:train")), db: Session = Depends(get_db)):
    task = db.get(TrainTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="训练任务不存在")
    dataset = db.get(Dataset, task.dataset_id)
    return {
        "id": task.id,
        "dataset_name": dataset.name if dataset else "",
        "status": task.status,
        "progress": task.progress,
        "error_message": task.error_message,
        "config": task.config_json,
        "log": tail_file(task.log_path),
        "created_at": dt(task.created_at),
        "finished_at": dt(task.finished_at),
    }


@router.post("/train/tasks/{task_id}/cancel")
def cancel_train(task_id: int, _: User = Depends(require("model:train")), db: Session = Depends(get_db)):
    task = db.get(TrainTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="训练任务不存在")
    if task.status == "PENDING":
        task.status = "CANCELLED"
        task.finished_at = datetime.now()
        db.commit()
        return {"status": task.status}
    if task.status in {"PREPROCESSING", "TRAINING", "EVALUATING"}:
        cancel_file(task.id).write_text("1", encoding="utf-8")
        return {"status": "CANCEL_REQUESTED"}
    raise HTTPException(status_code=400, detail="当前状态不能取消")


@router.get("/models")
def list_models(_: User = Depends(require("model:view")), db: Session = Depends(get_db)):
    rows = db.scalars(select(ModelVersion).order_by(ModelVersion.id.desc())).all()
    return [model_dict(db, row) for row in rows]


@router.get("/models/metrics")
def model_metrics(_: User = Depends(require("model:view")), db: Session = Depends(get_db)):
    return list_models(_, db)


@router.get("/models/compare")
def compare_models(
    left: int = Query(...),
    right: int = Query(...),
    _: User = Depends(require("model:compare")),
    db: Session = Depends(get_db),
):
    a = db.get(ModelVersion, left)
    b = db.get(ModelVersion, right)
    if a is None or b is None:
        raise HTTPException(status_code=404, detail="模型版本不存在")
    same = a.dataset_id == b.dataset_id
    return {
        "left": model_dict(db, a),
        "right": model_dict(db, b),
        "comparable": same,
        "message": "" if same else "数据划分不同，数值不能直接当作改进幅度",
    }


@router.post("/models/{model_id}/publish")
def publish_model(model_id: int, _: User = Depends(require("model:train")), db: Session = Depends(get_db)):
    model = db.get(ModelVersion, model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="模型版本不存在")
    db.query(ModelVersion).update({"published": 0})
    model.published = 1
    db.commit()
    clear_model_cache()
    return model_dict(db, model)


@router.post("/detect/single")
async def detect_single(
    file: UploadFile = File(...),
    user: User = Depends(require("detect:single")),
    db: Session = Depends(get_db),
):
    raw = await file.read()
    try:
        rows, _ = parse_upload(file.filename or "", raw, require_label=False, batch_limit=1)
    except MailParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if len(rows) != 1:
        raise HTTPException(status_code=400, detail="单封识别只接受一封邮件")
    try:
        loaded = load_published(db)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    task = DetectTask(user_id=user.id, model_id=loaded[0].id, mode="single", status="RUNNING", total_count=1, created_at=datetime.now())
    db.add(task)
    db.flush()
    result = infer_mail(db, rows[0], loaded)
    record = save_detection(db, task=task, mail=rows[0], result=result)
    task.status = "SUCCESS"
    task.done_count = 1
    task.finished_at = datetime.now()
    db.commit()
    return record_dict(db, record)


@router.post("/detect/batch")
async def detect_batch(
    file: UploadFile = File(...),
    user: User = Depends(require("detect:batch")),
    db: Session = Depends(get_db),
):
    raw = await file.read()
    try:
        rows, warnings = parse_upload(file.filename or "", raw, require_label=False, batch_limit=MAX_DETECT)
    except MailParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    version = db.scalar(select(ModelVersion).where(ModelVersion.published == 1))
    if version is None:
        raise HTTPException(status_code=400, detail="当前没有已发布模型")
    task = DetectTask(
        user_id=user.id,
        model_id=version.id,
        mode="batch",
        status="PENDING",
        total_count=len(rows),
        created_at=datetime.now(),
    )
    db.add(task)
    db.flush()
    folder = get_settings().data_path / "detect"
    folder.mkdir(parents=True, exist_ok=True)
    import joblib
    joblib.dump(rows, folder / f"{task.id}.joblib")
    db.commit()
    return {"task_id": task.id, "status": task.status, "total_count": task.total_count, "warnings": warnings}


@router.get("/detect/tasks/{task_id}")
def detect_task(task_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.get(DetectTask, task_id)
    if task is None or (task.user_id != user.id and not is_admin(db, user)):
        raise HTTPException(status_code=404, detail="识别任务不存在")
    records = db.scalars(select(DetectRecord).where(DetectRecord.task_id == task.id).order_by(DetectRecord.id)).all()
    return {
        "id": task.id,
        "status": task.status,
        "mode": task.mode,
        "total_count": task.total_count,
        "done_count": task.done_count,
        "error_message": task.error_message,
        "records": [record_dict(db, row) for row in records],
    }


@router.get("/detect/records")
def detect_records(
    page: int = 1,
    size: int = 10,
    user: User = Depends(require("detect:history")),
    db: Session = Depends(get_db),
):
    page, size = page_args(page, size)
    stmt = select(DetectRecord)
    if not is_admin(db, user):
        stmt = stmt.where(DetectRecord.user_id == user.id)
    rows = db.scalars(stmt.order_by(DetectRecord.id.desc())).all()
    return {
        "items": [record_dict(db, row) for row in rows[(page - 1) * size: page * size]],
        "total": len(rows),
        "page": page,
        "size": size,
    }


@router.put("/detect/records/{record_id}/feedback")
def feedback(record_id: int, body: FeedbackIn, user: User = Depends(require("detect:history")), db: Session = Depends(get_db)):
    if body.feedback not in {"phish", "ham"}:
        raise HTTPException(status_code=400, detail="反馈只能是 phish 或 ham")
    record = owned_record(db, user, record_id)
    record.feedback = body.feedback
    db.commit()
    return record_dict(db, record)


@router.post("/detect/records/{record_id}/commit-graph")
def commit_detect_graph(record_id: int, user: User = Depends(require("kg:edit")), db: Session = Depends(get_db)):
    record = owned_record(db, user, record_id)
    payload = record.graph_json or {}
    nodes = payload.get("nodes") or {}
    edges = [(item["rel"], item["src"], item["dst"]) for item in payload.get("edges") or []]
    write_extraction(
        db,
        {"nodes": nodes, "edges": edges},
        count_label=record.feedback or record.pred_label,
        sample_key=f"detect:{record.id}",
    )
    audit(db, user.id, "commit-detect", f"detect:{record.id}", None, {"label": record.feedback or record.pred_label})
    db.commit()
    return {"ok": True}


def _record_filters(db: Session, user: User, start: str, end: str, model_id: int | None, user_id: int | None):
    stmt = select(DetectRecord)
    if is_admin(db, user):
        if user_id:
            stmt = stmt.where(DetectRecord.user_id == user_id)
    else:
        stmt = stmt.where(DetectRecord.user_id == user.id)
    if model_id:
        stmt = stmt.where(DetectRecord.model_id == model_id)
    if start:
        stmt = stmt.where(DetectRecord.created_at >= datetime.fromisoformat(start))
    if end:
        stmt = stmt.where(DetectRecord.created_at < datetime.fromisoformat(end) + timedelta(days=1))
    return db.scalars(stmt.order_by(DetectRecord.created_at)).all()


@router.get("/stats/overview")
def stats_overview(
    start: str = "",
    end: str = "",
    model_id: int | None = None,
    user_id: int | None = None,
    user: User = Depends(require("stats:view")),
    db: Session = Depends(get_db),
):
    rows = _record_filters(db, user, start, end, model_id, user_id)
    trend: dict[str, dict] = {}
    pie = {"phish": 0, "ham": 0}
    feedback_bucket: dict[str, list[int]] = {}
    for row in rows:
        day = row.created_at.strftime("%Y-%m-%d")
        trend.setdefault(day, {"date": day, "phish": 0, "ham": 0})
        trend[day][row.pred_label] = trend[day].get(row.pred_label, 0) + 1
        if row.pred_label in pie:
            pie[row.pred_label] += 1
        if row.feedback in {"phish", "ham"}:
            feedback_bucket.setdefault(day, [0, 0])
            feedback_bucket[day][1] += 1
            if row.feedback == row.pred_label:
                feedback_bucket[day][0] += 1
    features: dict[str, int] = {}
    if rows:
        ids = [row.id for row in rows]
        evidences = db.scalars(select(DetectEvidence).where(DetectEvidence.record_id.in_(ids))).all()
        for item in evidences:
            features[item.entity_type or "未知"] = features.get(item.entity_type or "未知", 0) + 1
    return {
        "trend": [trend[key] for key in sorted(trend)],
        "pie": pie,
        "features": [{"type": key, "count": value} for key, value in sorted(features.items())],
        "feedback_accuracy": [
            {"date": key, "accuracy": round(value[0] / value[1], 4), "count": value[1]}
            for key, value in sorted(feedback_bucket.items())
        ],
    }


@router.get("/stats/export")
def stats_export(
    start: str = "",
    end: str = "",
    model_id: int | None = None,
    user_id: int | None = None,
    user: User = Depends(require("stats:export")),
    db: Session = Depends(get_db),
):
    from fastapi.responses import Response

    rows = _record_filters(db, user, start, end, model_id, user_id)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["时间", "主题", "预测", "置信度", "模型分", "图谱分", "反馈"])
    for row in rows:
        writer.writerow([dt(row.created_at), row.subject, row.pred_label, row.confidence, row.p_gnn, row.p_rule, row.feedback or ""])
    return Response(
        "\ufeff" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=detect-records.csv"},
    )


@router.get("/kg/subgraph")
def subgraph(
    types: str = "",
    keyword: str = "",
    min_risk: float | None = None,
    limit: int = 150,
    _: User = Depends(require("kg:view")),
    db: Session = Depends(get_db),
):
    limit = min(max(limit, 1), 300)
    selected = [item for item in types.split(",") if item] or None
    data = get_graph(db).subgraph(selected, keyword or None, min_risk, limit)
    if data["total"] > 300:
        raise HTTPException(status_code=400, detail="节点过多，请缩小筛选条件")
    data["truncated"] = data["total"] > limit
    return data


@router.get("/kg/path")
def kg_path(
    from_id: str,
    to_id: str,
    max_hop: int = 4,
    _: User = Depends(require("kg:view")),
    db: Session = Depends(get_db),
):
    return graph_call(lambda: get_graph(db).shortest_path(from_id, to_id, min(max_hop, 4)))


@router.put("/kg/node")
def update_kg_node_by_body(body: NodeIn, user: User = Depends(require("kg:edit")), db: Session = Depends(get_db)):
    if not body.id:
        raise HTTPException(status_code=400, detail="缺少节点编号")
    return update_kg_node(body.id, body, user, db)


@router.delete("/kg/node")
def delete_kg_node_by_query(
    id: str,
    cascade: bool = False,
    user: User = Depends(require("kg:edit")),
    db: Session = Depends(get_db),
):
    return delete_kg_node(id, cascade, user, db)


@router.get("/kg/nodes/{node_id:path}")
def kg_node(node_id: str, _: User = Depends(require("kg:view")), db: Session = Depends(get_db)):
    node = get_graph(db).get_node(node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="节点不存在")
    return node


@router.get("/kg/neighbors")
def kg_neighbors(id: str, _: User = Depends(require("kg:view")), db: Session = Depends(get_db)):
    return graph_call(lambda: get_graph(db).neighbors(id))


@router.put("/kg/nodes/{node_id:path}")
def update_kg_node(
    node_id: str,
    body: NodeIn,
    user: User = Depends(require("kg:edit")),
    db: Session = Depends(get_db),
):
    graph = get_graph(db)
    before = graph.get_node(node_id)
    if before is None:
        raise HTTPException(status_code=404, detail="节点不存在")
    after = graph_call(lambda: graph.update_node(
        node_id, name=body.name, remark=body.remark, locked=body.locked, manual_risk=body.manual_risk
    ))
    audit(db, user.id, "update-node", node_id, before, after)
    db.commit()
    return after


@router.delete("/kg/nodes/{node_id:path}")
def delete_kg_node(
    node_id: str,
    cascade: bool = False,
    user: User = Depends(require("kg:edit")),
    db: Session = Depends(get_db),
):
    graph = get_graph(db)
    before = graph.get_node(node_id)
    graph_call(lambda: graph.delete_node(node_id, cascade))
    audit(db, user.id, "delete-node", node_id, before, {"cascade": cascade})
    db.commit()
    return {"ok": True}


@router.post("/kg/relations")
def add_relation(body: RelationIn, user: User = Depends(require("kg:edit")), db: Session = Depends(get_db)):
    if body.rel not in REL_RULES:
        raise HTTPException(status_code=400, detail="未知关系类型")
    graph = get_graph(db)
    src = graph.get_node(body.source)
    dst = graph.get_node(body.target)
    if src is None or dst is None:
        raise HTTPException(status_code=404, detail="关系两端节点不存在")
    expect_src, expect_dst = REL_RULES[body.rel]
    if src["type"] != expect_src or dst["type"] != expect_dst:
        raise HTTPException(status_code=400, detail=f"{body.rel} 只能连接 {expect_src} 与 {expect_dst}")
    edge = graph.upsert_edge(body.rel, body.source, body.target)
    audit(db, user.id, "add-relation", f"{body.source}->{body.target}", None, edge)
    db.commit()
    return edge


@router.delete("/kg/relations/{edge_id}")
def delete_relation(edge_id: str, user: User = Depends(require("kg:edit")), db: Session = Depends(get_db)):
    graph = get_graph(db)
    target = int(edge_id) if isinstance(graph, SqlGraphStore) and edge_id.isdigit() else edge_id
    graph_call(lambda: graph.delete_edge(target))
    audit(db, user.id, "delete-relation", edge_id, None, None)
    db.commit()
    return {"ok": True}


@router.post("/kg/merge")
def merge_nodes(body: MergeIn, user: User = Depends(require("kg:edit")), db: Session = Depends(get_db)):
    graph = get_graph(db)
    graph_call(lambda: graph.merge_nodes(body.keep_id, body.drop_id))
    audit(db, user.id, "merge-node", body.drop_id, {"drop": body.drop_id}, {"keep": body.keep_id})
    db.commit()
    return {"ok": True}
