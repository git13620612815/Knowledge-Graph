"""2 层 mean-aggregator GraphSAGE，结构与设计说明书第 9 章一致。"""

import random
from copy import deepcopy

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from torch import nn

from app.ml.textutil import preprocess, tokenize

TYPE_INDEX = {
    "Email": 0,
    "Url": 1,
    "Domain": 2,
    "Ip": 3,
    "CertIssuer": 4,
    "Logo": 5,
    "Sender": 6,
    "Keyword": 7,
}
FUSION_GNN = 0.75
FUSION_RULE = 0.25


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def make_vectorizer(min_df: int) -> TfidfVectorizer:
    return TfidfVectorizer(
        preprocessor=preprocess,
        tokenizer=tokenize,
        token_pattern=None,
        max_features=5000,
        ngram_range=(1, 2),
        min_df=min_df,
    )


def vectorize_text(vectorizer: TfidfVectorizer, text: str) -> np.ndarray:
    vec = vectorizer.transform([text or ""])
    dense = vec.toarray().astype(np.float32).reshape(-1)
    if dense.shape[0] < 5000:
        dense = np.pad(dense, (0, 5000 - dense.shape[0]))
    return dense[:5000]


def length_bucket(length: int) -> float:
    if length < 20:
        return 0.0
    if length < 50:
        return 0.33
    if length < 100:
        return 0.66
    return 1.0


def used_risk(node: dict | None, train_stats: dict | None) -> tuple[float, bool]:
    in_graph = node is not None
    manual = (node or {}).get("manual_risk") or "unknown"
    if manual == "high":
        return 1.0, in_graph
    if manual == "low":
        return 0.0, in_graph
    if train_stats is not None:
        phish, ham = train_stats
        return round((phish + 1) / (phish + ham + 2), 4), in_graph
    if node is not None:
        return float(node.get("risk_score") or 0.5), True
    return 0.5, False


def build_graph(extracted: dict, risk_lookup) -> dict:
    nodes = extracted["nodes"]
    keys = list(nodes.keys())
    index = {key: i for i, key in enumerate(keys)}
    x = np.zeros((len(keys), 32), dtype=np.float32)
    risks = {}
    for key, node in nodes.items():
        info = risk_lookup(key, node["type"])
        risk, in_graph = info
        risks[key] = risk
        feat = x[index[key]]
        feat[TYPE_INDEX.get(node["type"], 0)] = 1
        props = node.get("props") or {}
        if node["type"] in {"Url", "Domain"}:
            feat[8] = length_bucket(int(props.get("length") or len(node.get("name") or "")))
            feat[9] = float(props.get("digit_ratio") or 0)
            feat[10] = float(props.get("special_ratio") or 0)
            feat[11] = min(float(props.get("subdomain_count") or 0) / 5, 1)
        feat[12] = 1 if props.get("has_ip_host") else 0
        feat[13] = 1 if props.get("brand_lookalike") else 0
        feat[14] = float(risk)
        feat[15] = 1 if in_graph else 0
    pairs = []
    for rel, src, dst in extracted["edges"]:
        if src not in index or dst not in index:
            continue
        pairs.append((index[src], index[dst]))
        pairs.append((index[dst], index[src]))
    if pairs:
        edge_index = np.array(pairs, dtype=np.int64).T
    else:
        edge_index = np.zeros((2, 0), dtype=np.int64)
    return {"x": x, "edge_index": edge_index, "keys": keys, "risks": risks, "nodes": nodes, "edges": extracted["edges"]}


class GraphSAGE(nn.Module):
    def __init__(self, dropout: float = 0.3):
        super().__init__()
        self.l1s = nn.Linear(32, 64)
        self.l1n = nn.Linear(32, 64)
        self.l2s = nn.Linear(64, 64)
        self.l2n = nn.Linear(64, 64)
        self.text = nn.Linear(5000, 64)
        self.f1 = nn.Linear(192, 64)
        self.f2 = nn.Linear(64, 1)
        self.drop_p = dropout

    def sage(self, x, edge_index, lin_s, lin_n):
        n = x.size(0)
        if edge_index.numel() == 0:
            neigh = torch.zeros_like(x)
        else:
            src, dst = edge_index
            neigh = torch.zeros_like(x)
            deg = torch.zeros(n, 1, device=x.device)
            neigh.index_add_(0, dst, x[src])
            ones = torch.ones(src.size(0), 1, device=x.device)
            deg.index_add_(0, dst, ones)
            neigh = neigh / deg.clamp(min=1)
        return lin_s(x) + lin_n(neigh)

    def forward(self, x, edge_index, text_vec):
        h = F.relu(self.sage(x, edge_index, self.l1s, self.l1n))
        h = F.dropout(h, self.drop_p, training=self.training)
        h = F.relu(self.sage(h, edge_index, self.l2s, self.l2n))
        pooled = torch.cat([h.mean(dim=0), h.max(dim=0).values], dim=0)
        text_h = F.relu(self.text(text_vec))
        z = torch.cat([pooled, text_h], dim=0)
        z = F.dropout(F.relu(self.f1(z)), self.drop_p, training=self.training)
        return self.f2(z).squeeze(-1)


def _forward_graph(model, graph, text_vec):
    x = torch.tensor(graph["x"], dtype=torch.float32)
    edge_index = torch.tensor(graph["edge_index"], dtype=torch.long)
    text = torch.tensor(text_vec, dtype=torch.float32)
    return model(x, edge_index, text)


def predict_proba(model: GraphSAGE, graph: dict, text_vec: np.ndarray) -> float:
    model.eval()
    with torch.no_grad():
        logit = _forward_graph(model, graph, text_vec)
        return float(torch.sigmoid(logit).item())


def rule_score(graph: dict) -> tuple[float, list[dict]]:
    hit_types = {"Url", "Domain", "Sender", "Logo", "CertIssuer", "Ip"}
    hits = []
    for key, node in graph["nodes"].items():
        if node["type"] not in hit_types:
            continue
        risk = float(graph["risks"].get(key, 0.5))
        in_graph = graph["x"][graph["keys"].index(key)][15] > 0
        if in_graph and risk >= 0.6:
            hits.append({"id": key, "type": node["type"], "name": node["name"], "risk": risk})
    if not hits:
        return 0.5, []
    hits.sort(key=lambda item: item["risk"], reverse=True)
    score = max(item["risk"] for item in hits) * 0.7 + min(1, len(hits) / 3) * 0.3
    return max(0.0, min(1.0, score)), hits


def evidence_paths(graph: dict, hits: list[dict], limit: int = 5) -> list[dict]:
    if not hits:
        return []
    adj: dict[str, list[tuple[str, str]]] = {}
    for rel, src, dst in graph["edges"]:
        adj.setdefault(src, []).append((dst, rel))
        adj.setdefault(dst, []).append((src, rel))
    email_ids = [key for key, node in graph["nodes"].items() if node["type"] == "Email"]
    if not email_ids:
        return []
    start = email_ids[0]
    wanted = {item["id"]: item for item in hits}
    found = []
    queue = [(start, [])]
    seen = {start}
    while queue and len(found) < limit:
        current, path = queue.pop(0)
        if len(path) >= 4:
            continue
        for nxt, rel in adj.get(current, []):
            step = path + [(current, rel, nxt)]
            if nxt in wanted and nxt not in {item["hit_id"] for item in found}:
                found.append({"hit_id": nxt, "steps": step, "hit": wanted[nxt]})
            if nxt in seen:
                continue
            seen.add(nxt)
            queue.append((nxt, step))
    found.sort(key=lambda item: item["hit"]["risk"], reverse=True)
    results = []
    for item in found[:limit]:
        parts = []
        for src, rel, dst in item["steps"]:
            if not parts:
                src_node = graph["nodes"][src]
                parts.append(f"{src_node['type']}|{src_node['name']}")
            dst_node = graph["nodes"][dst]
            parts.append(rel)
            parts.append(f"{dst_node['type']}|{dst_node['name']}")
        results.append({
            "path_text": " -> ".join(parts)[:1000],
            "risk_score": round(item["hit"]["risk"], 4),
            "entity_type": item["hit"]["type"],
        })
    return results


def fuse(p_gnn: float, p_rule: float, w_gnn: float = FUSION_GNN, w_rule: float = FUSION_RULE) -> dict:
    p = w_gnn * p_gnn + w_rule * p_rule
    label = "phish" if p >= 0.5 else "ham"
    confidence = 0.5 + abs(p - 0.5)
    return {
        "pred_label": label,
        "confidence": round(confidence, 4),
        "p_gnn": round(p_gnn, 4),
        "p_rule": round(p_rule, 4),
        "p_final": round(p, 4),
    }


def _scores(model, rows) -> tuple[list[int], list[float]]:
    ys, ps = [], []
    for row in rows:
        ys.append(int(row["y"]))
        ps.append(predict_proba(model, row["graph"], row["text"]))
    return ys, ps


def _f1_of(model, rows) -> float:
    if not rows:
        return 0.0
    ys, ps = _scores(model, rows)
    pred = [1 if p >= 0.5 else 0 for p in ps]
    return float(f1_score(ys, pred, zero_division=0))


def train_graphs(rows: list[dict], config: dict, log) -> tuple[GraphSAGE, dict]:
    set_seed(int(config.get("seed", 42)))
    train_rows = [r for r in rows if r["split"] == "train"]
    val_rows = [r for r in rows if r["split"] == "val"]
    test_rows = [r for r in rows if r["split"] == "test"]
    if not train_rows:
        raise RuntimeError("训练集为空，无法训练")
    phish = sum(r["y"] == 1 for r in train_rows)
    ham = sum(r["y"] == 0 for r in train_rows)
    pos_weight = 1.0
    if phish:
        pos_weight = min(5.0, ham / phish if ham else 1.0)
    model = GraphSAGE(dropout=float(config.get("dropout", 0.3)))
    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=float(config.get("lr", 0.001)),
        weight_decay=float(config.get("weight_decay", 0.0001)),
    )
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([pos_weight], dtype=torch.float32))
    epochs = int(config.get("epoch", 40))
    batch_size = int(config.get("batch_size", 32))
    patience = int(config.get("patience", 8))
    early = bool(config.get("early_stop", True))
    best_state = deepcopy(model.state_dict())
    best_f1 = -1.0
    stale = 0
    monitor = val_rows or train_rows
    if not val_rows:
        log("验证集为空，早停改为观察训练集 F1")
    def cancelled() -> bool:
        flag = config.get("cancelled")
        return bool(flag()) if callable(flag) else bool(flag)

    for epoch in range(1, epochs + 1):
        if cancelled():
            raise RuntimeError("训练已取消")
        order = train_rows[:]
        rnd = random.Random(int(config.get("seed", 42)) + epoch)
        rnd.shuffle(order)
        model.train()
        total_loss = 0.0
        seen = 0
        for start in range(0, len(order), batch_size):
            batch = order[start:start + batch_size]
            optimizer.zero_grad()
            loss_acc = None
            for row in batch:
                logit = _forward_graph(model, row["graph"], row["text"])
                target = torch.tensor(float(row["y"]), dtype=torch.float32)
                loss = loss_fn(logit.view(1), target.view(1))
                loss_acc = loss if loss_acc is None else loss_acc + loss
            loss_mean = loss_acc / len(batch)
            loss_mean.backward()
            optimizer.step()
            total_loss += float(loss_mean.item()) * len(batch)
            seen += len(batch)
        val_f1 = _f1_of(model, monitor)
        if epoch % 5 == 0 or epoch == epochs:
            log(f"epoch {epoch}/{epochs} 训练损失 {total_loss / max(seen, 1):.4f} 验证集 F1 {val_f1:.4f}")
        if val_f1 > best_f1 + 1e-6:
            best_f1 = val_f1
            best_state = deepcopy(model.state_dict())
            stale = 0
        else:
            stale += 1
            if early and stale >= patience:
                log(f"验证集 F1 连续 {patience} 个 epoch 未提升，提前停止")
                break
        if config.get("progress_cb"):
            config["progress_cb"](int(epoch / epochs * 90) + 5)
    model.load_state_dict(best_state)
    metrics = evaluate_rows(model, test_rows or monitor)
    metrics["val_f1"] = round(best_f1, 4)
    return model, metrics


def evaluate_rows(model: GraphSAGE, rows: list[dict]) -> dict:
    if not rows:
        return {
            "accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "auc": None,
            "confusion_matrix": [[0, 0], [0, 0]], "roc": {"fpr": [], "tpr": []}, "test_count": 0,
        }
    ys, ps = _scores(model, rows)
    pred = [1 if p >= 0.5 else 0 for p in ps]
    cm = confusion_matrix(ys, pred, labels=[0, 1]).tolist()
    auc = None
    fpr, tpr = [], []
    if len(set(ys)) > 1:
        auc = float(roc_auc_score(ys, ps))
        fpr_a, tpr_a, _ = roc_curve(ys, ps)
        if len(fpr_a) > 200:
            idx = np.linspace(0, len(fpr_a) - 1, 200).astype(int)
            fpr_a, tpr_a = fpr_a[idx], tpr_a[idx]
        fpr = [round(float(v), 6) for v in fpr_a]
        tpr = [round(float(v), 6) for v in tpr_a]
    return {
        "accuracy": round(float(accuracy_score(ys, pred)), 4),
        "precision": round(float(precision_score(ys, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(ys, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(ys, pred, zero_division=0)), 4),
        "auc": None if auc is None else round(auc, 4),
        "confusion_matrix": cm,
        "roc": {"fpr": fpr, "tpr": tpr},
        "test_count": len(rows),
    }
