from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def main() -> None:
    with TestClient(app) as client:
        secret = Path("data/initial_admin_password.txt").read_text(encoding="utf-8")
        password = secret.split("初始密码: ", 1)[1].splitlines()[0].strip()
        login = client.post("/api/auth/login", json={"account": "admin", "password": password})
        print("login", login.status_code, login.json().get("detail", "ok"))
        token = login.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        changed = client.put(
            "/api/profile/password",
            json={"old_password": password, "new_password": "Admin12345"},
            headers=headers,
        )
        print("password", changed.status_code, changed.text[:200])
        headers = {"Authorization": f"Bearer {changed.json()['token']}"}
        sample = client.post("/api/datasets/sample", headers=headers)
        print("sample", sample.status_code, sample.text[:300])
        dataset_id = sample.json()["id"]
        task = client.post(
            "/api/train/tasks",
            json={"dataset_id": dataset_id, "epoch": 8, "batch_size": 16, "early_stop": True, "seed": 42},
            headers=headers,
        )
        print("train", task.status_code, task.text[:300])
        task_id = task.json()["id"]
        status = "PENDING"
        for _ in range(90):
            detail = client.get(f"/api/train/tasks/{task_id}", headers=headers)
            body = detail.json()
            status = body["status"]
            print("status", status, body.get("progress"), (body.get("log") or "").splitlines()[-1:])
            if status in {"SUCCESS", "FAILED", "CANCELLED"}:
                if status != "SUCCESS":
                    print(body.get("log"))
                break
            import time
            time.sleep(2)
        assert status == "SUCCESS", status
        models = client.get("/api/models", headers=headers).json()
        published = client.post(f"/api/models/{models[0]['id']}/publish", headers=headers)
        print("publish", published.status_code, published.json()["version_no"])
        mail = "Subject: 账户异常\n请立即验证 http://paypa1.com/login?id=99\n".encode()
        detected = client.post(
            "/api/detect/single",
            files={"file": ("mail.txt", mail, "text/plain")},
            headers=headers,
        )
        print("detect", detected.status_code, detected.text[:500])
        graph = client.get("/api/kg/subgraph", headers=headers)
        print("graph", graph.status_code, graph.json().get("total"), len(graph.json().get("nodes", [])))
        stats = client.get("/api/stats/overview", headers=headers)
        print("stats", stats.status_code, stats.json()["pie"])
        denied = client.get("/api/admin/users")
        print("no-token", denied.status_code)


if __name__ == "__main__":
    main()
