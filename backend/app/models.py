from datetime import datetime

from sqlalchemy import JSON, BigInteger, DateTime, Index, Integer, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def now() -> datetime:
    return datetime.now()


class User(Base):
    __tablename__ = "sys_user"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    phone: Mapped[str | None] = mapped_column(String(20))
    password_hash: Mapped[str] = mapped_column(String(100), nullable=False)
    nickname: Mapped[str] = mapped_column(String(40), nullable=False)
    avatar_path: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    fail_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime)
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    must_change_password: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)


class Role(Base):
    __tablename__ = "sys_role"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(32), nullable=False)
    parent_role_id: Mapped[int | None] = mapped_column(BigInteger)
    builtin: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    remark: Mapped[str | None] = mapped_column(String(200))


class Permission(Base):
    __tablename__ = "sys_permission"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)


class UserRole(Base):
    __tablename__ = "sys_user_role"
    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    role_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)


class RolePermission(Base):
    __tablename__ = "sys_role_permission"
    role_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    permission_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)


class EmailVerifyCode(Base):
    __tablename__ = "email_verify_code"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    purpose: Mapped[str] = mapped_column(String(16), nullable=False)
    code_hash: Mapped[str] = mapped_column(String(100), nullable=False)
    expire_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class Dataset(Base):
    __tablename__ = "dataset"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    parent_id: Mapped[int | None] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="READY")
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    phish_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ham_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now)


class MailSample(Base):
    __tablename__ = "mail_sample"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    dataset_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    body: Mapped[str] = mapped_column(Text, nullable=False)
    from_addr: Mapped[str | None] = mapped_column(String(255))
    label: Mapped[str | None] = mapped_column(String(8))
    split: Mapped[str | None] = mapped_column(String(8))
    file_path: Mapped[str | None] = mapped_column(String(255))
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now)


class CertSnapshot(Base):
    __tablename__ = "cert_snapshot"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    not_after: Mapped[str | None] = mapped_column(String(32))


class TrainTask(Base):
    __tablename__ = "train_task"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    dataset_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    config_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    log_path: Mapped[str] = mapped_column(String(255), nullable=False)
    error_message: Mapped[str | None] = mapped_column(String(500))
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)


class ModelVersion(Base):
    __tablename__ = "model_version"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    dataset_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    version_no: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    published: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    weight_path: Mapped[str] = mapped_column(String(255), nullable=False)
    tfidf_path: Mapped[str] = mapped_column(String(255), nullable=False)
    config_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    metrics_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now)


class DetectTask(Base):
    __tablename__ = "detect_task"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    model_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mode: Mapped[str] = mapped_column(String(8), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    total_count: Mapped[int] = mapped_column(Integer, nullable=False)
    done_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)


class DetectRecord(Base):
    __tablename__ = "detect_record"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    model_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    pred_label: Mapped[str] = mapped_column(String(8), nullable=False)
    confidence: Mapped[float] = mapped_column(Numeric(6, 4), nullable=False)
    p_gnn: Mapped[float] = mapped_column(Numeric(6, 4), nullable=False)
    p_rule: Mapped[float] = mapped_column(Numeric(6, 4), nullable=False)
    p_final: Mapped[float] = mapped_column(Numeric(6, 4), nullable=False)
    feedback: Mapped[str | None] = mapped_column(String(8))
    summary_json: Mapped[list | None] = mapped_column(JSON)
    graph_json: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now, index=True)


class DetectEvidence(Base):
    __tablename__ = "detect_evidence"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    record_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    path_text: Mapped[str] = mapped_column(String(1000), nullable=False)
    risk_score: Mapped[float] = mapped_column(Numeric(6, 4), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class KgAudit(Base):
    __tablename__ = "kg_audit"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    operator_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    before_json: Mapped[dict | None] = mapped_column(JSON)
    after_json: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now)


class KgNode(Base):
    __tablename__ = "kg_node"
    biz_id: Mapped[str] = mapped_column(String(512), primary_key=True)
    ntype: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    props: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    phish_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ham_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[float] = mapped_column(Numeric(8, 4), nullable=False, default=0.5)
    locked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    manual_risk: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    remark: Mapped[str | None] = mapped_column(String(500))


class KgEdge(Base):
    __tablename__ = "kg_edge"
    __table_args__ = (
        Index("uk_edge", "rel_type", "src", "dst", unique=True, mysql_length={"src": 300, "dst": 300}),
    )
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    rel_type: Mapped[str] = mapped_column(String(32), nullable=False)
    src: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    dst: Mapped[str] = mapped_column(String(512), nullable=False, index=True)


class KgCountLog(Base):
    __tablename__ = "kg_count_log"
    node_id: Mapped[str] = mapped_column(String(512), primary_key=True)
    sample_key: Mapped[str] = mapped_column(String(64), primary_key=True)


class ExtractedTriple(Base):
    __tablename__ = "extracted_triple"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    dataset_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    sample_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    head_id: Mapped[str] = mapped_column(String(512), nullable=False)
    head_type: Mapped[str] = mapped_column(String(32), nullable=False)
    head_name: Mapped[str] = mapped_column(String(500), nullable=False)
    head_props: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    rel: Mapped[str] = mapped_column(String(32), nullable=False)
    tail_id: Mapped[str] = mapped_column(String(512), nullable=False)
    tail_type: Mapped[str] = mapped_column(String(32), nullable=False)
    tail_name: Mapped[str] = mapped_column(String(500), nullable=False)
    tail_props: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
