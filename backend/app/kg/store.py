import json
import logging
import uuid

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import KgCountLog, KgEdge, KgNode

logger = logging.getLogger("phishkg.kg")

NODE_TYPES = {"Email", "Url", "Domain", "Ip", "CertIssuer", "Logo", "Sender", "Keyword"}
REL_RULES = {
    "CONTAINS_URL": ("Email", "Url"),
    "HOSTED_ON": ("Url", "Domain"),
    "RESOLVES_TO": ("Domain", "Ip"),
    "ISSUED_BY": ("Domain", "CertIssuer"),
    "HAS_LOGO": ("Email", "Logo"),
    "SENT_BY": ("Email", "Sender"),
    "REDIRECTS_TO": ("Url", "Url"),
    "MENTIONS": ("Email", "Keyword"),
    "SIMILAR_LOGO": ("Logo", "Logo"),
}
COUNT_TYPES = {"Url", "Domain", "Sender", "Logo", "CertIssuer", "Ip"}


def _risk(phish: int, ham: int) -> float:
    return round((phish + 1) / (phish + ham + 2), 4)


def _props_to_json(props: dict | None) -> str:
    return json.dumps(props or {}, ensure_ascii=False)


def _props_from_json(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def node_dict(node: KgNode) -> dict:
    return {
        "id": node.biz_id,
        "type": node.ntype,
        "name": node.name,
        "props": node.props or {},
        "phish_count": node.phish_count,
        "ham_count": node.ham_count,
        "risk_score": float(node.risk_score or 0.5),
        "locked": bool(node.locked),
        "manual_risk": node.manual_risk or "unknown",
        "remark": node.remark or "",
    }


class SqlGraphStore:
    def __init__(self, db: Session):
        self.db = db

    def get_node(self, biz_id: str) -> dict | None:
        node = self.db.get(KgNode, biz_id)
        return node_dict(node) if node else None

    def upsert_node(self, biz_id: str, ntype: str, name: str, props: dict | None = None, protect_locked: bool = True) -> dict:
        node = self.db.get(KgNode, biz_id)
        if node is None:
            node = KgNode(
                biz_id=biz_id,
                ntype=ntype,
                name=(name or biz_id)[:500],
                props=props or {},
                risk_score=0.5,
                manual_risk="unknown",
            )
            self.db.add(node)
            self.db.flush()
            return node_dict(node)
        if protect_locked and node.locked:
            return node_dict(node)
        if name:
            node.name = name[:500]
        if props:
            merged = dict(node.props or {})
            merged.update(props)
            node.props = merged
        self.db.flush()
        return node_dict(node)

    def upsert_edge(self, rel: str, src: str, dst: str) -> dict:
        found = self.db.scalar(select(KgEdge).where(KgEdge.rel_type == rel, KgEdge.src == src, KgEdge.dst == dst))
        if found:
            return {"id": found.id, "rel": rel, "source": src, "target": dst}
        edge = KgEdge(rel_type=rel, src=src, dst=dst)
        self.db.add(edge)
        self.db.flush()
        return {"id": edge.id, "rel": rel, "source": src, "target": dst}

    def update_node(self, biz_id: str, *, name: str | None, remark: str | None, locked: bool | None, manual_risk: str | None) -> dict:
        node = self.db.get(KgNode, biz_id)
        if node is None:
            raise KeyError(biz_id)
        if name is not None:
            node.name = name[:500]
        if remark is not None:
            node.remark = remark[:500]
        if locked is not None:
            node.locked = 1 if locked else 0
        if manual_risk is not None:
            if manual_risk not in {"unknown", "low", "high"}:
                raise ValueError("风险标记只能是 unknown、low 或 high")
            node.manual_risk = manual_risk
        self.db.flush()
        return node_dict(node)

    def delete_node(self, biz_id: str, cascade: bool = False) -> None:
        node = self.db.get(KgNode, biz_id)
        if node is None:
            raise KeyError(biz_id)
        edges = self.db.scalars(select(KgEdge).where(or_(KgEdge.src == biz_id, KgEdge.dst == biz_id))).all()
        if edges and not cascade:
            raise RuntimeError("节点仍有关系，请先删除关系或选择级联删除")
        for edge in edges:
            self.db.delete(edge)
        self.db.delete(node)
        self.db.flush()

    def delete_edge(self, edge_id: int) -> None:
        edge = self.db.get(KgEdge, edge_id)
        if edge is None:
            raise KeyError(edge_id)
        self.db.delete(edge)
        self.db.flush()

    def merge_nodes(self, keep_id: str, drop_id: str) -> None:
        if keep_id == drop_id:
            raise ValueError("不能合并同一个节点")
        keep = self.db.get(KgNode, keep_id)
        drop = self.db.get(KgNode, drop_id)
        if keep is None or drop is None:
            raise KeyError("节点不存在")
        if keep.ntype != drop.ntype:
            raise ValueError("只能合并相同类型的节点")
        edges = self.db.scalars(select(KgEdge).where(or_(KgEdge.src == drop_id, KgEdge.dst == drop_id))).all()
        for edge in edges:
            src = keep_id if edge.src == drop_id else edge.src
            dst = keep_id if edge.dst == drop_id else edge.dst
            if src == dst:
                self.db.delete(edge)
                continue
            exists = self.db.scalar(select(KgEdge).where(KgEdge.rel_type == edge.rel_type, KgEdge.src == src, KgEdge.dst == dst))
            if exists:
                self.db.delete(edge)
            else:
                edge.src = src
                edge.dst = dst
        keep.phish_count += drop.phish_count
        keep.ham_count += drop.ham_count
        keep.risk_score = _risk(keep.phish_count, keep.ham_count)
        self.db.delete(drop)
        self.db.flush()

    def bump_counts(self, biz_ids: list[str], label: str, sample_key: str) -> None:
        if label not in {"phish", "ham"}:
            return
        for biz_id in set(biz_ids):
            node = self.db.get(KgNode, biz_id)
            if node is None or node.locked or node.ntype not in COUNT_TYPES:
                continue
            existed = self.db.scalar(
                select(KgCountLog).where(KgCountLog.node_id == biz_id, KgCountLog.sample_key == sample_key)
            )
            if existed:
                continue
            self.db.add(KgCountLog(node_id=biz_id, sample_key=sample_key))
            if label == "phish":
                node.phish_count += 1
            else:
                node.ham_count += 1
            node.risk_score = _risk(node.phish_count, node.ham_count)
        self.db.flush()

    def known_logos(self) -> list[str]:
        rows = self.db.scalars(select(KgNode).where(KgNode.ntype == "Logo")).all()
        return [row.props.get("phash") or row.name for row in rows]

    def subgraph(self, types: list[str] | None, keyword: str | None, min_risk: float | None, limit: int) -> dict:
        stmt = select(KgNode)
        if types:
            stmt = stmt.where(KgNode.ntype.in_(types))
        if keyword:
            stmt = stmt.where(KgNode.name.contains(keyword))
        if min_risk is not None:
            stmt = stmt.where(KgNode.risk_score >= min_risk)
        total = len(self.db.scalars(stmt).all())
        rows = self.db.scalars(stmt.order_by(KgNode.risk_score.desc()).limit(limit)).all()
        ids = {row.biz_id for row in rows}
        edges = []
        if ids:
            all_edges = self.db.scalars(select(KgEdge).where(KgEdge.src.in_(ids), KgEdge.dst.in_(ids))).all()
            edges = [{"id": e.id, "source": e.src, "target": e.dst, "rel": e.rel_type} for e in all_edges]
        return {"nodes": [node_dict(row) for row in rows], "edges": edges, "total": total}

    def neighbors(self, biz_id: str) -> dict:
        if self.db.get(KgNode, biz_id) is None:
            raise KeyError(biz_id)
        edges = self.db.scalars(select(KgEdge).where(or_(KgEdge.src == biz_id, KgEdge.dst == biz_id))).all()
        ids = {biz_id}
        for edge in edges:
            ids.add(edge.src)
            ids.add(edge.dst)
        nodes = self.db.scalars(select(KgNode).where(KgNode.biz_id.in_(ids))).all()
        return {
            "nodes": [node_dict(node) for node in nodes],
            "edges": [{"id": e.id, "source": e.src, "target": e.dst, "rel": e.rel_type} for e in edges],
        }

    def shortest_path(self, src: str, dst: str, max_hop: int = 4) -> dict:
        if self.db.get(KgNode, src) is None or self.db.get(KgNode, dst) is None:
            raise KeyError("节点不存在")
        if src == dst:
            node = self.get_node(src)
            return {"nodes": [node], "rels": []}
        edges = self.db.scalars(select(KgEdge)).all()
        adj: dict[str, list[tuple[str, str]]] = {}
        for edge in edges:
            adj.setdefault(edge.src, []).append((edge.dst, edge.rel_type))
            adj.setdefault(edge.dst, []).append((edge.src, edge.rel_type))
        queue = [(src, [])]
        seen = {src}
        found = None
        while queue:
            current, path = queue.pop(0)
            if len(path) >= max_hop:
                continue
            for nxt, rel in adj.get(current, []):
                if nxt in seen:
                    continue
                step = path + [{"source": current, "target": nxt, "rel": rel}]
                if nxt == dst:
                    found = step
                    queue = []
                    break
                seen.add(nxt)
                queue.append((nxt, step))
        if not found:
            return {"nodes": [], "rels": []}
        ordered = [src] + [step["target"] for step in found]
        nodes = []
        for biz_id in ordered:
            item = self.get_node(biz_id)
            if item:
                nodes.append(item)
        return {"nodes": nodes, "rels": found}

    def existing_ids(self, biz_ids: list[str]) -> set[str]:
        if not biz_ids:
            return set()
        rows = self.db.scalars(select(KgNode.biz_id).where(KgNode.biz_id.in_(list(set(biz_ids))))).all()
        return set(rows)


class Neo4jGraphStore:
    """Neo4j 实现。连接失败时由工厂回退到 SQL 图存储。"""

    def __init__(self, uri: str, user: str, password: str):
        from neo4j import GraphDatabase

        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.driver.verify_connectivity()

    def close(self):
        self.driver.close()

    def _run(self, cypher: str, **params):
        with self.driver.session() as session:
            return list(session.run(cypher, **params))

    def get_node(self, biz_id: str) -> dict | None:
        rows = self._run("MATCH (n:Entity {biz_id:$id}) RETURN n LIMIT 1", id=biz_id)
        if not rows:
            return None
        return self._node(rows[0]["n"])

    def _node(self, n) -> dict:
        return {
            "id": n["biz_id"],
            "type": n["ntype"],
            "name": n["name"],
            "props": _props_from_json(n.get("props")),
            "phish_count": n.get("phish_count") or 0,
            "ham_count": n.get("ham_count") or 0,
            "risk_score": float(n.get("risk_score") or 0.5),
            "locked": bool(n.get("locked")),
            "manual_risk": n.get("manual_risk") or "unknown",
            "remark": n.get("remark") or "",
        }

    def upsert_node(self, biz_id: str, ntype: str, name: str, props: dict | None = None, protect_locked: bool = True) -> dict:
        if ntype not in NODE_TYPES:
            raise ValueError("未知实体类型")
        rows = self._run(
            """
            MERGE (n:Entity {biz_id:$id})
            ON CREATE SET n.ntype=$ntype, n.name=$name, n.props=$props,
              n.phish_count=0, n.ham_count=0, n.risk_score=0.5,
              n.locked=false, n.manual_risk='unknown', n.remark=''
            RETURN n
            """,
            id=biz_id,
            ntype=ntype,
            name=(name or biz_id)[:500],
            props=_props_to_json(props),
        )
        node = self._node(rows[0]["n"])
        if protect_locked and node["locked"]:
            return node
        self._run(f"MATCH (n:Entity {{biz_id:$id}}) SET n:{ntype}", id=biz_id)
        if not node["locked"]:
            rows = self._run(
                """
                MATCH (n:Entity {biz_id:$id})
                SET n.ntype=$ntype, n.name=$name, n.props=$props
                RETURN n
                """,
                id=biz_id,
                ntype=ntype,
                name=(name or biz_id)[:500],
                props=_props_to_json({**(node.get("props") or {}), **(props or {})}),
            )
            return self._node(rows[0]["n"])
        return node

    def upsert_edge(self, rel: str, src: str, dst: str) -> dict:
        if rel not in REL_RULES:
            raise ValueError("未知关系类型")
        eid = uuid.uuid4().hex
        rows = self._run(
            f"""
            MATCH (a:Entity {{biz_id:$src}}), (b:Entity {{biz_id:$dst}})
            MERGE (a)-[r:{rel} {{rel_type:$rel}}]->(b)
            ON CREATE SET r.eid=$eid
            RETURN r.eid AS eid
            """,
            src=src,
            dst=dst,
            rel=rel,
            eid=eid,
        )
        if not rows:
            raise KeyError("关系两端节点不存在")
        return {"id": rows[0]["eid"], "rel": rel, "source": src, "target": dst}

    def update_node(self, biz_id, *, name, remark, locked, manual_risk) -> dict:
        node = self.get_node(biz_id)
        if node is None:
            raise KeyError(biz_id)
        if manual_risk is not None and manual_risk not in {"unknown", "low", "high"}:
            raise ValueError("风险标记只能是 unknown、low 或 high")
        rows = self._run(
            """
            MATCH (n:Entity {biz_id:$id})
            SET n.name = coalesce($name, n.name),
                n.remark = coalesce($remark, n.remark),
                n.locked = coalesce($locked, n.locked),
                n.manual_risk = coalesce($manual, n.manual_risk)
            RETURN n
            """,
            id=biz_id,
            name=name,
            remark=remark,
            locked=locked,
            manual=manual_risk,
        )
        return self._node(rows[0]["n"])

    def delete_node(self, biz_id: str, cascade: bool = False) -> None:
        if self.get_node(biz_id) is None:
            raise KeyError(biz_id)
        rows = self._run("MATCH (n:Entity {biz_id:$id})-[r]-() RETURN count(r) AS c", id=biz_id)
        if rows and rows[0]["c"] and not cascade:
            raise RuntimeError("节点仍有关系，请先删除关系或选择级联删除")
        self._run("MATCH (n:Entity {biz_id:$id}) DETACH DELETE n", id=biz_id)

    def delete_edge(self, edge_id) -> None:
        rows = self._run("MATCH ()-[r {eid:$eid}]-() DELETE r RETURN count(r) AS c", eid=str(edge_id))
        if not rows:
            raise KeyError(edge_id)

    def merge_nodes(self, keep_id: str, drop_id: str) -> None:
        if keep_id == drop_id:
            raise ValueError("不能合并同一个节点")
        keep = self.get_node(keep_id)
        drop = self.get_node(drop_id)
        if not keep or not drop:
            raise KeyError("节点不存在")
        if keep["type"] != drop["type"]:
            raise ValueError("只能合并相同类型的节点")
        rels = self._run(
            "MATCH (drop:Entity {biz_id:$drop})-[r]-(other:Entity) RETURN type(r) AS t, r.rel_type AS rel, other.biz_id AS other, startNode(r).biz_id AS src",
            drop=drop_id,
        )
        for row in rels:
            src = keep_id if row["src"] == drop_id else row["other"]
            dst = row["other"] if row["src"] == drop_id else keep_id
            if src != dst:
                self.upsert_edge(row["rel"] or row["t"], src, dst)
        phish = keep["phish_count"] + drop["phish_count"]
        ham = keep["ham_count"] + drop["ham_count"]
        self._run(
            "MATCH (n:Entity {biz_id:$id}) SET n.phish_count=$p, n.ham_count=$h, n.risk_score=$r",
            id=keep_id,
            p=phish,
            h=ham,
            r=_risk(phish, ham),
        )
        self.delete_node(drop_id, cascade=True)

    def bump_counts(self, biz_ids: list[str], label: str, sample_key: str) -> None:
        if label not in {"phish", "ham"}:
            return
        for biz_id in set(biz_ids):
            node = self.get_node(biz_id)
            if node is None or node["locked"] or node["type"] not in COUNT_TYPES:
                continue
            rows = self._run(
                "MATCH (n:Entity {biz_id:$id}) RETURN $key IN coalesce(n.counted, []) AS seen",
                id=biz_id,
                key=sample_key,
            )
            if rows and rows[0]["seen"]:
                continue
            field = "phish_count" if label == "phish" else "ham_count"
            self._run(
                f"""
                MATCH (n:Entity {{biz_id:$id}})
                SET n.{field} = coalesce(n.{field}, 0) + 1,
                    n.counted = coalesce(n.counted, []) + $key
                WITH n
                SET n.risk_score = (n.phish_count + 1.0) / (n.phish_count + n.ham_count + 2.0)
                """,
                id=biz_id,
                key=sample_key,
            )

    def known_logos(self) -> list[str]:
        rows = self._run("MATCH (n:Entity {ntype:'Logo'}) RETURN n.name AS name")
        return [row["name"] for row in rows]

    def subgraph(self, types, keyword, min_risk, limit) -> dict:
        where = ["1=1"]
        params = {"limit": limit}
        if types:
            where.append("n.ntype IN $types")
            params["types"] = types
        if keyword:
            where.append("toLower(n.name) CONTAINS toLower($keyword)")
            params["keyword"] = keyword
        if min_risk is not None:
            where.append("n.risk_score >= $min_risk")
            params["min_risk"] = min_risk
        cond = " AND ".join(where)
        total = self._run(f"MATCH (n:Entity) WHERE {cond} RETURN count(n) AS c", **params)[0]["c"]
        rows = self._run(
            f"MATCH (n:Entity) WHERE {cond} RETURN n ORDER BY n.risk_score DESC LIMIT $limit",
            **params,
        )
        ids = [self._node(row["n"])["id"] for row in rows]
        edges = []
        if ids:
            erows = self._run(
                """
                MATCH (a:Entity)-[r]->(b:Entity)
                WHERE a.biz_id IN $ids AND b.biz_id IN $ids
                RETURN coalesce(r.eid, id(r)) AS id, a.biz_id AS source, b.biz_id AS target, r.rel_type AS rel
                """,
                ids=ids,
            )
            edges = [{"id": e["id"], "source": e["source"], "target": e["target"], "rel": e["rel"]} for e in erows]
        return {"nodes": [self._node(row["n"]) for row in rows], "edges": edges, "total": total}

    def neighbors(self, biz_id: str) -> dict:
        if self.get_node(biz_id) is None:
            raise KeyError(biz_id)
        rows = self._run(
            """
            MATCH (n:Entity {biz_id:$id})-[r]-(m:Entity)
            RETURN n, r, m, startNode(r).biz_id AS src, endNode(r).biz_id AS dst, r.rel_type AS rel, coalesce(r.eid, id(r)) AS eid
            """,
            id=biz_id,
        )
        nodes = {biz_id: self.get_node(biz_id)}
        edges = []
        for row in rows:
            other = self._node(row["m"])
            nodes[other["id"]] = other
            edges.append({"id": row["eid"], "source": row["src"], "target": row["dst"], "rel": row["rel"]})
        return {"nodes": list(nodes.values()), "edges": edges}

    def shortest_path(self, src: str, dst: str, max_hop: int = 4) -> dict:
        if self.get_node(src) is None or self.get_node(dst) is None:
            raise KeyError("节点不存在")
        hop = min(max(int(max_hop), 1), 4)
        rows = self._run(
            f"""
            MATCH (a:Entity {{biz_id:$src}}), (b:Entity {{biz_id:$dst}})
            MATCH p = shortestPath((a)-[*..{hop}]-(b))
            RETURN [n IN nodes(p) | n.biz_id] AS ids,
                   [r IN relationships(p) | r.rel_type] AS rels
            """,
            src=src,
            dst=dst,
        )
        if not rows:
            return {"nodes": [], "rels": []}
        ids = rows[0]["ids"]
        rels = rows[0]["rels"]
        nodes = [self.get_node(i) for i in ids]
        steps = []
        for i, rel in enumerate(rels):
            steps.append({"source": ids[i], "target": ids[i + 1], "rel": rel})
        return {"nodes": nodes, "rels": steps}

    def existing_ids(self, biz_ids: list[str]) -> set[str]:
        if not biz_ids:
            return set()
        rows = self._run("MATCH (n:Entity) WHERE n.biz_id IN $ids RETURN n.biz_id AS id", ids=list(set(biz_ids)))
        return {row["id"] for row in rows}


_neo4j: Neo4jGraphStore | None = None
_neo4j_failed = False


def get_graph(db: Session):
    global _neo4j, _neo4j_failed
    from app.core.config import get_settings

    settings = get_settings()
    if settings.neo4j_uri and not _neo4j_failed:
        try:
            if _neo4j is None:
                _neo4j = Neo4jGraphStore(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
            return _neo4j
        except Exception:
            logger.warning("Neo4j 不可用，已回退到关系数据库中的图谱表", exc_info=True)
            _neo4j_failed = True
    return SqlGraphStore(db)
