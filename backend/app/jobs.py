import logging
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path

import joblib
import torch
from sklearn.model_selection import train_test_split
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db import SessionLocal
from app.kg.extract import COUNT_TYPES, extract_mail
from app.kg.store import get_graph
from app.ml.engine import (
    build_graph,
    fuse,
    make_vectorizer,
    predict_proba,
    rule_score,
    evidence_paths,
    train_graphs,
    used_risk,
    vectorize_text,
    GraphSAGE,
)
from app.ml.textutil import preprocess, tokenize
from app.models import (
    CertSnapshot,
    Dataset,
    DetectEvidence,
    DetectRecord,
    DetectTask,
    ExtractedTriple,
    MailSample,
    ModelVersion,
    TrainTask,
)
from app.service import content_hash, store_triples, write_extraction

logger = logging.getLogger("phishkg.worker")
_model_cache: dict[int, tuple] = {}


class TaskLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, message: str) -> None:
        line = f"{datetime.now():%Y-%m-%d %H:%M:%S} {message}\n"
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        logger.info(message)


def tail_file(path: str, lines: int = 200) -> str:
    file = Path(path)
    if not file.exists():
        return ""
    content = file.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(content[-lines:])


def cancel_file(task_id: int) -> Path:
    path = get_settings().data_path / "cancel" / str(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _update_task(task_id: int, **values) -> None:
    db = SessionLocal()
    try:
        task = db.get(TrainTask, task_id)
        if task is None:
            return
        for key, value in values.items():
            setattr(task, key, value)
        db.commit()
    finally:
        db.close()


def _assign_splits(samples: list[MailSample], seed: int, log: TaskLog) -> None:
    if samples and all(sample.split in {"train", "val", "test"} for sample in samples):
        log("沿用数据集中已有的训练、验证、测试划分")
        return
    labels = [sample.label for sample in samples]
    indexes = list(range(len(samples)))
    try:
        train_idx, temp_idx = train_test_split(indexes, test_size=0.3, random_state=seed, stratify=labels)
        temp_labels = [labels[i] for i in temp_idx]
        val_idx, test_idx = train_test_split(temp_idx, test_size=0.5, random_state=seed, stratify=temp_labels)
    except ValueError:
        log("样本过少，无法分层划分，已按顺序切分")
        cut1 = max(1, int(len(samples) * 0.7))
        cut2 = max(cut1 + 1, int(len(samples) * 0.85))
        train_idx, val_idx, test_idx = indexes[:cut1], indexes[cut1:cut2], indexes[cut2:] or indexes[-1:]
    for idx in train_idx:
        samples[idx].split = "train"
    for idx in val_idx:
        samples[idx].split = "val"
    for idx in test_idx:
        samples[idx].split = "test"
    log(f"数据划分完成：训练 {len(train_idx)}，验证 {len(val_idx)}，测试 {len(test_idx)}")


def _dropped_keys(db: Session, dataset_id: int) -> dict[int, set[tuple]]:
    rows = db.scalars(
        select(ExtractedTriple).where(ExtractedTriple.dataset_id == dataset_id, ExtractedTriple.status == "dropped")
    ).all()
    grouped: dict[int, set[tuple]] = {}
    for row in rows:
        grouped.setdefault(row.sample_id, set()).add((row.head_id, row.rel, row.tail_id))
    return grouped


def _prepare_extract(sample: MailSample, cert_map, vectorizer, known_logos, dropped) -> dict:
    extracted = extract_mail(
        sample_key=str(sample.id),
        subject=sample.subject,
        body=sample.body,
        from_addr=sample.from_addr,
        cert_map=cert_map,
        vectorizer=vectorizer,
        known_logos=known_logos,
    )
    banned = dropped.get(sample.id, set())
    if banned:
        extracted["edges"] = [edge for edge in extracted["edges"] if (edge[1], edge[0], edge[2]) not in banned]
    kept_ids = {extracted["email_id"]}
    for rel, src, dst in extracted["edges"]:
        kept_ids.add(src)
        kept_ids.add(dst)
    extracted["nodes"] = {key: value for key, value in extracted["nodes"].items() if key in kept_ids}
    return extracted


def run_train(task_id: int) -> None:
    db = SessionLocal()
    log = None
    try:
        task = db.get(TrainTask, task_id)
        if task is None:
            return
        log = TaskLog(Path(task.log_path)).write
        dataset = db.get(Dataset, task.dataset_id)
        if dataset is None or dataset.status == "DELETED":
            raise RuntimeError("数据集不存在或已删除")
        samples = db.scalars(select(MailSample).where(MailSample.dataset_id == dataset.id)).all()
        samples = [sample for sample in samples if sample.label in {"phish", "ham"} and (sample.body or "").strip()]
        if len(samples) < 4:
            raise RuntimeError("有效标注样本少于 4 封，无法划分数据集")
        config = dict(task.config_json or {})
        seed = int(config.get("seed", 42))
        _assign_splits(samples, seed, log)
        db.commit()
        _update_task(task_id, status="PREPROCESSING", progress=5, started_at=task.started_at or datetime.now())
        log("[预处理] 解码完成，样本 %d 封" % len(samples))
        for sample in samples:
            preprocess(f"{sample.subject}\n{sample.body}")
        log("[预处理] 分词完成")
        for sample in samples:
            tokenize(preprocess(f"{sample.subject}\n{sample.body}"))
        log("[预处理] 去停用词完成")
        train_samples = [sample for sample in samples if sample.split == "train"]
        min_df = 2 if len(train_samples) >= 200 else 1
        vectorizer = make_vectorizer(min_df)
        corpus = [f"{sample.subject}\n{sample.body}" for sample in train_samples]
        vectorizer.fit(corpus)
        if not vectorizer.vocabulary_:
            vectorizer = make_vectorizer(1)
            vectorizer.fit(corpus)
        log(f"[预处理] TF-IDF 拟合完成，词表大小 {len(vectorizer.vocabulary_)}，min_df={min_df}")
        if cancel_file(task_id).exists():
            raise RuntimeError("训练已取消")
        cert_map = {row.domain: row.issuer for row in db.scalars(select(CertSnapshot)).all()}
        graph = get_graph(db)
        known = graph.known_logos()
        dropped = _dropped_keys(db, dataset.id)
        prepared = []
        train_counts: dict[str, list[int]] = {}
        sample_entities: dict[int, set[str]] = {}
        for sample in samples:
            extracted = _prepare_extract(sample, cert_map, vectorizer, known, dropped)
            entity_ids = {key for key, node in extracted["nodes"].items() if node["type"] in COUNT_TYPES}
            sample_entities[sample.id] = entity_ids
            if sample.split == "train":
                bucket = 0 if sample.label == "phish" else 1
                for entity_id in entity_ids:
                    train_counts.setdefault(entity_id, [0, 0])[bucket] += 1
            prepared.append((sample, extracted))
        node_cache = {}

        def risk_lookup(sample: MailSample, biz_id: str, _ntype: str):
            if biz_id not in node_cache:
                node_cache[biz_id] = graph.get_node(biz_id)
            stats = None
            if biz_id in train_counts:
                phish, ham = train_counts[biz_id]
                if sample.split == "train" and biz_id in sample_entities.get(sample.id, set()):
                    if sample.label == "phish":
                        phish -= 1
                    else:
                        ham -= 1
                if phish + ham > 0:
                    stats = (phish, ham)
            return used_risk(node_cache.get(biz_id), stats)

        rows = []
        for sample, extracted in prepared:
            graph_data = build_graph(extracted, lambda biz_id, ntype, sample=sample: risk_lookup(sample, biz_id, ntype))
            rows.append({
                "split": sample.split,
                "y": 1 if sample.label == "phish" else 0,
                "graph": graph_data,
                "text": vectorize_text(vectorizer, f"{sample.subject}\n{sample.body}"),
                "sample": sample,
                "extracted": extracted,
            })
        log(f"[预处理] 构图完成，图数量 {len(rows)}")
        _update_task(task_id, status="TRAINING", progress=10)
        config["cancelled"] = lambda: cancel_file(task_id).exists()
        config["progress_cb"] = lambda value: _update_task(task_id, progress=value, status="TRAINING")
        model, metrics = train_graphs(rows, config, log)
        _update_task(task_id, status="EVALUATING", progress=95)
        log(
            "测试集评估完成：准确率 %(accuracy)s，精确率 %(precision)s，召回率 %(recall)s，F1 %(f1)s，AUC %(auc)s"
            % metrics
        )
        for sample, extracted in prepared:
            write_extraction(
                db,
                extracted,
                count_label=sample.label if sample.split == "train" else None,
                sample_key=f"train:{sample.id}",
            )
        db.query(ExtractedTriple).filter(
            ExtractedTriple.dataset_id == dataset.id,
            ExtractedTriple.status == "pending",
        ).update({"status": "kept"})
        version_no = datetime.now().strftime("%Y%m%d-%H%M%S")
        folder = get_settings().data_path / "models" / version_no
        folder.mkdir(parents=True, exist_ok=True)
        weight_path = folder / "model.pt"
        tfidf_path = folder / "tfidf.joblib"
        torch.save(model.state_dict(), weight_path)
        joblib.dump(vectorizer, tfidf_path)
        version = ModelVersion(
            task_id=task_id,
            dataset_id=dataset.id,
            version_no=version_no,
            published=0,
            weight_path=str(weight_path),
            tfidf_path=str(tfidf_path),
            config_json=config_without_callbacks(task.config_json, dataset.name),
            metrics_json=metrics,
            sample_count=len(samples),
            created_at=datetime.now(),
        )
        db.add(version)
        task = db.get(TrainTask, task_id)
        task.status = "SUCCESS"
        task.progress = 100
        task.finished_at = datetime.now()
        db.commit()
        log(f"模型版本 {version_no} 已保存，发布后才会用于识别")
    except Exception as exc:
        db.rollback()
        message = str(exc)[:500]
        _update_task(
            task_id,
            status="CANCELLED" if "取消" in message else "FAILED",
            error_message=message,
            finished_at=datetime.now(),
        )
        if log:
            log(message)
            log(traceback.format_exc())
        logger.exception("训练失败")
    finally:
        db.close()


def config_without_callbacks(config: dict, dataset_name: str) -> dict:
    clean = {key: value for key, value in (config or {}).items() if key not in {"cancelled", "progress_cb"}}
    clean["dataset_name"] = dataset_name
    clean["fusion_gnn"] = 0.75
    clean["fusion_rule"] = 0.25
    return clean


def load_published(db: Session) -> tuple[ModelVersion, GraphSAGE, object]:
    version = db.scalar(select(ModelVersion).where(ModelVersion.published == 1))
    if version is None:
        raise RuntimeError("当前没有已发布模型")
    cached = _model_cache.get(version.id)
    if cached:
        return cached
    dropout = float((version.config_json or {}).get("dropout", 0.3))
    model = GraphSAGE(dropout=dropout)
    model.load_state_dict(torch.load(version.weight_path, map_location="cpu", weights_only=True))
    model.eval()
    vectorizer = joblib.load(version.tfidf_path)
    _model_cache[version.id] = (version, model, vectorizer)
    return _model_cache[version.id]


def clear_model_cache(model_id: int | None = None) -> None:
    if model_id is None:
        _model_cache.clear()
    else:
        _model_cache.pop(model_id, None)


def infer_mail(db: Session, mail: dict, loaded=None) -> dict:
    version, model, vectorizer = loaded or load_published(db)
    cert_map = {row.domain: row.issuer for row in db.scalars(select(CertSnapshot)).all()}
    graph = get_graph(db)
    extracted = extract_mail(
        sample_key=f"detect-{datetime.now().strftime('%H%M%S%f')}",
        subject=mail.get("subject") or "",
        body=mail.get("body") or "",
        from_addr=mail.get("from_addr"),
        html=mail.get("html") or "",
        images=mail.get("images") or [],
        cert_map=cert_map,
        vectorizer=vectorizer,
        known_logos=graph.known_logos(),
    )
    existing = graph.existing_ids(list(extracted["nodes"].keys()))

    def lookup(biz_id: str, _ntype: str):
        node = graph.get_node(biz_id) if biz_id in existing else None
        return used_risk(node, None)

    graph_data = build_graph(extracted, lookup)
    text = vectorize_text(vectorizer, f"{mail.get('subject') or ''}\n{mail.get('body') or ''}")
    p_gnn = predict_proba(model, graph_data, text)
    p_rule, hits = rule_score(graph_data)
    fused = fuse(
        p_gnn,
        p_rule,
        float((version.config_json or {}).get("fusion_gnn", 0.75)),
        float((version.config_json or {}).get("fusion_rule", 0.25)),
    )
    summary = [
        {"type": node["type"], "name": node["name"]}
        for node in extracted["nodes"].values()
        if node["type"] != "Email"
    ][:30]
    return {
        **fused,
        "model_id": version.id,
        "model_version": version.version_no,
        "summary": summary,
        "evidences": evidence_paths(graph_data, hits),
        "graph": {
            "nodes": extracted["nodes"],
            "edges": [{"rel": rel, "src": src, "dst": dst} for rel, src, dst in extracted["edges"]],
        },
    }


def save_detection(db: Session, *, task: DetectTask, mail: dict, result: dict) -> DetectRecord:
    record = DetectRecord(
        task_id=task.id,
        user_id=task.user_id,
        model_id=result["model_id"],
        subject=(mail.get("subject") or "")[:500],
        pred_label=result["pred_label"],
        confidence=result["confidence"],
        p_gnn=result["p_gnn"],
        p_rule=result["p_rule"],
        p_final=result["p_final"],
        summary_json=result["summary"],
        graph_json=result["graph"],
        created_at=datetime.now(),
    )
    db.add(record)
    db.flush()
    for item in result["evidences"]:
        db.add(DetectEvidence(
            record_id=record.id,
            path_text=item["path_text"],
            risk_score=item["risk_score"],
            entity_type=item["entity_type"],
        ))
    return record


def run_detect_task(task_id: int) -> None:
    db = SessionLocal()
    try:
        task = db.get(DetectTask, task_id)
        if task is None or task.status != "PENDING":
            return
        task.status = "RUNNING"
        db.commit()
        payload_path = get_settings().data_path / "detect" / f"{task_id}.joblib"
        mails = joblib.load(payload_path)
        loaded = load_published(db)
        for mail in mails:
            result = infer_mail(db, mail, loaded)
            save_detection(db, task=task, mail=mail, result=result)
            task.done_count += 1
            if task.done_count % 10 == 0:
                db.commit()
        task.status = "SUCCESS"
        task.finished_at = datetime.now()
        db.commit()
    except Exception as exc:
        db.rollback()
        task = db.get(DetectTask, task_id)
        if task:
            task.status = "FAILED"
            task.error_message = str(exc)[:500]
            task.finished_at = datetime.now()
            db.commit()
        logger.exception("批量识别失败")
    finally:
        db.close()


def worker_loop(stop: threading.Event | None = None) -> None:
    while not (stop and stop.is_set()):
        db = SessionLocal()
        try:
            running = db.scalar(
                select(TrainTask.id).where(TrainTask.status.in_(["PREPROCESSING", "TRAINING", "EVALUATING"]))
            )
            pending_id = None
            if running is None:
                pending_id = db.scalar(select(TrainTask.id).where(TrainTask.status == "PENDING").order_by(TrainTask.id))
            detect_id = db.scalar(select(DetectTask.id).where(DetectTask.status == "PENDING", DetectTask.mode == "batch").order_by(DetectTask.id))
        finally:
            db.close()
        if pending_id:
            claimed = SessionLocal()
            try:
                updated = claimed.query(TrainTask).filter(TrainTask.id == pending_id, TrainTask.status == "PENDING").update(
                    {"status": "PREPROCESSING", "started_at": datetime.now()}
                )
                claimed.commit()
            finally:
                claimed.close()
            if updated == 1:
                run_train(pending_id)
        elif detect_id:
            run_detect_task(detect_id)
        if stop:
            stop.wait(2)
        else:
            time.sleep(2)


_worker_started = False
_worker_stop: threading.Event | None = None


def ensure_worker() -> threading.Event:
    global _worker_started, _worker_stop
    if _worker_stop is None:
        _worker_stop = threading.Event()
    if not _worker_started:
        threading.Thread(target=worker_loop, args=(_worker_stop,), daemon=True, name="phishkg-worker").start()
        _worker_started = True
    return _worker_stop
