import hashlib
import logging
import re
import secrets
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import hash_password
from app.kg.extract import COUNT_TYPES, extract_mail
from app.kg.store import get_graph
from app.models import (
    Dataset,
    ExtractedTriple,
    KgAudit,
    MailSample,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)

logger = logging.getLogger("phishkg")

PERMISSIONS = [
    ("profile:read", "查看个人资料"),
    ("profile:update", "修改个人资料"),
    ("kg:view", "查看知识图谱"),
    ("kg:edit", "编辑知识图谱"),
    ("detect:single", "单封识别"),
    ("detect:batch", "批量识别"),
    ("detect:history", "识别记录"),
    ("stats:view", "查看统计"),
    ("stats:export", "导出统计"),
    ("model:view", "查看模型指标"),
    ("model:compare", "模型版本对比"),
    ("user:manage", "用户管理"),
    ("role:manage", "角色权限管理"),
    ("dataset:manage", "数据集管理"),
    ("model:train", "模型训练"),
]
USER_CODES = {
    "profile:read", "profile:update", "kg:view", "detect:single", "detect:batch",
    "detect:history", "stats:view", "stats:export", "model:view", "model:compare",
}
ADMIN_CODES = {"kg:edit", "user:manage", "role:manage", "dataset:manage", "model:train"}


def content_hash(subject: str, body: str) -> str:
    text = re.sub(r"\s+", " ", f"{subject or ''} {body or ''}".strip().lower())
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def refresh_counts(db: Session, dataset: Dataset) -> None:
    rows = db.scalars(select(MailSample).where(MailSample.dataset_id == dataset.id)).all()
    dataset.sample_count = len(rows)
    dataset.phish_count = sum(1 for row in rows if row.label == "phish")
    dataset.ham_count = sum(1 for row in rows if row.label == "ham")


def audit(db: Session, operator_id: int, action: str, target: str, before: dict | None, after: dict | None) -> None:
    db.add(KgAudit(
        operator_id=operator_id,
        action=action,
        target=target[:255],
        before_json=before,
        after_json=after,
        created_at=datetime.now(),
    ))


def role_chain(db: Session, role_id: int | None) -> list[Role]:
    chain = []
    seen = set()
    current = role_id
    while current and current not in seen and len(chain) < 6:
        seen.add(current)
        role = db.get(Role, current)
        if role is None:
            break
        chain.append(role)
        current = role.parent_role_id
    return chain


def effective_permission_codes(db: Session, user: User) -> list[str]:
    role_ids = db.scalars(select(UserRole.role_id).where(UserRole.user_id == user.id)).all()
    codes: set[str] = set()
    for role_id in role_ids:
        chain = role_chain(db, role_id)[:3]
        if len(chain) >= 3 and chain[-1].parent_role_id:
            logger.debug("角色继承超过 3 层，已截断 role=%s", role_id)
        ids = [role.id for role in chain]
        if not ids:
            continue
        perm_ids = db.scalars(select(RolePermission.permission_id).where(RolePermission.role_id.in_(ids))).all()
        if perm_ids:
            names = db.scalars(select(Permission.code).where(Permission.id.in_(perm_ids))).all()
            codes.update(names)
    return sorted(codes)


def user_role_codes(db: Session, user_id: int) -> list[str]:
    role_ids = db.scalars(select(UserRole.role_id).where(UserRole.user_id == user_id)).all()
    if not role_ids:
        return []
    return db.scalars(select(Role.code).where(Role.id.in_(role_ids))).all()


def is_admin(db: Session, user: User) -> bool:
    return "user:manage" in effective_permission_codes(db, user)


def enabled_admin_count(db: Session) -> int:
    role = db.scalar(select(Role).where(Role.code == "ADMIN"))
    if role is None:
        return 0
    ids = db.scalars(select(UserRole.user_id).where(UserRole.role_id == role.id)).all()
    if not ids:
        return 0
    return int(db.scalar(select(func.count()).select_from(User).where(User.id.in_(ids), User.status == 1)) or 0)


def store_triples(db: Session, dataset_id: int, sample: MailSample, extracted: dict) -> None:
    nodes = extracted["nodes"]
    for rel, src, dst in extracted["edges"]:
        if src not in nodes or dst not in nodes:
            continue
        head, tail = nodes[src], nodes[dst]
        db.add(ExtractedTriple(
            dataset_id=dataset_id,
            sample_id=sample.id,
            head_id=src,
            head_type=head["type"],
            head_name=head["name"],
            head_props=head.get("props") or {},
            rel=rel,
            tail_id=dst,
            tail_type=tail["type"],
            tail_name=tail["name"],
            tail_props=tail.get("props") or {},
            status="pending",
        ))


def commit_triple_rows(db: Session, rows: list[ExtractedTriple], *, count_label: str | None, sample_key: str) -> int:
    graph = get_graph(db)
    count_ids = []
    for row in rows:
        if row.status == "dropped":
            continue
        graph.upsert_node(row.head_id, row.head_type, row.head_name, row.head_props or {})
        graph.upsert_node(row.tail_id, row.tail_type, row.tail_name, row.tail_props or {})
        graph.upsert_edge(row.rel, row.head_id, row.tail_id)
        row.status = "kept"
        if row.head_type in COUNT_TYPES:
            count_ids.append(row.head_id)
        if row.tail_type in COUNT_TYPES:
            count_ids.append(row.tail_id)
    if count_label:
        graph.bump_counts(count_ids, count_label, sample_key)
    return len(rows)


def write_extraction(db: Session, extracted: dict, *, count_label: str | None, sample_key: str) -> None:
    graph = get_graph(db)
    nodes = extracted["nodes"]
    count_ids = []
    for biz_id, node in nodes.items():
        graph.upsert_node(biz_id, node["type"], node["name"], node.get("props") or {})
        if node["type"] in COUNT_TYPES:
            count_ids.append(biz_id)
    for rel, src, dst in extracted["edges"]:
        if src in nodes and dst in nodes:
            graph.upsert_edge(rel, src, dst)
    if count_label:
        graph.bump_counts(count_ids, count_label, sample_key)


def init_database() -> None:
    from app.db import Base, SessionLocal, engine

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.scalar(select(func.count()).select_from(Permission)) == 0:
            for code, name in PERMISSIONS:
                db.add(Permission(code=code, name=name))
            db.flush()
            user_role = Role(code="USER", name="普通用户", builtin=1, remark="默认识别与查看权限")
            db.add(user_role)
            db.flush()
            admin_role = Role(code="ADMIN", name="系统管理员", parent_role_id=user_role.id, builtin=1, remark="继承普通用户并具备管理权限")
            db.add(admin_role)
            db.flush()
            perm_by_code = {item.code: item for item in db.scalars(select(Permission)).all()}
            for code in USER_CODES:
                db.add(RolePermission(role_id=user_role.id, permission_id=perm_by_code[code].id))
            for code in ADMIN_CODES:
                db.add(RolePermission(role_id=admin_role.id, permission_id=perm_by_code[code].id))
        admin = db.scalar(select(User).where(User.username == "admin"))
        if admin is None:
            password = "Ad" + f"{secrets.randbelow(900000) + 100000}" + "x"
            admin_role = db.scalar(select(Role).where(Role.code == "ADMIN"))
            admin = User(
                username="admin",
                email="admin@phishkg.local",
                password_hash=hash_password(password),
                nickname="管理员",
                status=1,
                must_change_password=1,
                created_at=datetime.now(),
            )
            db.add(admin)
            db.flush()
            db.add(UserRole(user_id=admin.id, role_id=admin_role.id))
            secret_file = get_settings().data_path / "initial_admin_password.txt"
            secret_file.write_text(
                "用户名: admin\n邮箱: admin@phishkg.local\n初始密码: "
                + password
                + "\n请首次登录后立即修改。\n",
                encoding="utf-8",
            )
            logger.warning("已创建管理员 admin，初始密码已写入 %s", secret_file)
        db.commit()
    finally:
        db.close()
