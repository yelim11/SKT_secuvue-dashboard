from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path

import paramiko
from cryptography.fernet import Fernet
from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "secuvue.db"
KEY_PATH = DATA_DIR / "secret.key"
DATA_DIR.mkdir(exist_ok=True)

app = Flask(__name__)

KNOWN_SERVICES = [
    ("SSH", ["sshd", "ssh"]),
    ("DNS", ["named", "bind9"]),
    ("Web", ["httpd", "apache2", "nginx"]),
    ("DB", ["mariadb", "mysql", "mysqld"]),
    ("IDS", ["suricata", "snort3", "snort"]),
]

LOG_FILES = [
    ("/var/log/secure", "auth"),
    ("/var/log/auth.log", "auth"),
    ("/var/log/httpd/access_log", "web"),
    ("/var/log/httpd/error_log", "web"),
    ("/var/log/apache2/access.log", "web"),
    ("/var/log/apache2/error.log", "web"),
    ("/var/log/suricata/fast.log", "ids"),
]


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS systems (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                username TEXT NOT NULL,
                password_enc TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'unknown',
                os_name TEXT DEFAULT '',
                hostname TEXT DEFAULT '',
                last_seen TEXT,
                last_error TEXT DEFAULT '',
                cpu REAL DEFAULT 0,
                memory REAL DEFAULT 0,
                disk REAL DEFAULT 0,
                uptime_seconds INTEGER DEFAULT 0,
                services_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                UNIQUE(host, port, username)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                system_id INTEGER NOT NULL,
                system_name TEXT NOT NULL,
                ip TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                FOREIGN KEY(system_id) REFERENCES systems(id) ON DELETE CASCADE
            )
            """
        )


def load_fernet():
    if not KEY_PATH.exists():
        KEY_PATH.write_bytes(Fernet.generate_key())
    return Fernet(KEY_PATH.read_bytes())


FERNET = None


def encrypt_password(value: str) -> str:
    return FERNET.encrypt(value.encode()).decode()


def decrypt_password(value: str) -> str:
    return FERNET.decrypt(value.encode()).decode()


def ssh_client(system):
    client = paramiko.SSHClient()
    # 실습용: 운영 환경에서는 known_hosts 검증을 권장합니다.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=system["host"],
        port=int(system["port"]),
        username=system["username"],
        password=decrypt_password(system["password_enc"]),
        timeout=6,
        banner_timeout=6,
        auth_timeout=6,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_cmd(client, command, timeout=10):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    return out, err


def collect_services(client):
    result = {}
    for label, candidates in KNOWN_SERVICES:
        state = "not-found"
        service_name = ""
        for service in candidates:
            active, _ = run_cmd(client, f"systemctl is-active {service} 2>/dev/null || true")
            if active.strip() == "active":
                state, service_name = "active", service
                break
            exists, _ = run_cmd(
                client,
                f"systemctl list-unit-files --type=service 2>/dev/null | grep -q '^{service}\\.service' && echo yes || true",
            )
            if exists.strip() == "yes":
                state, service_name = "inactive", service
                break
        result[label] = {"service": service_name, "state": state}
    return result


def collect_metrics(client):
    hostname, _ = run_cmd(client, "hostname")
    os_name, _ = run_cmd(
        client,
        "sh -c '. /etc/os-release 2>/dev/null; printf \"%s\" \"${PRETTY_NAME:-Linux}\"'",
    )
    cpu_cmd = r'''sh -c '
read cpu user nice system idle iowait irq softirq steal guest guest_nice < /proc/stat
t1=$((user+nice+system+idle+iowait+irq+softirq+steal)); i1=$((idle+iowait))
sleep 0.25
read cpu user nice system idle iowait irq softirq steal guest guest_nice < /proc/stat
t2=$((user+nice+system+idle+iowait+irq+softirq+steal)); i2=$((idle+iowait))
dt=$((t2-t1)); di=$((i2-i1))
awk -v dt="$dt" -v di="$di" "BEGIN { if (dt>0) printf \"%.1f\", (dt-di)*100/dt; else print 0 }"
' '''
    cpu, _ = run_cmd(client, cpu_cmd)
    memory, _ = run_cmd(
        client,
        "awk '/MemTotal:/{t=$2}/MemAvailable:/{a=$2} END{if(t>0) printf \"%.1f\",(t-a)*100/t; else print 0}' /proc/meminfo",
    )
    disk, _ = run_cmd(client, "df -P / | awk 'NR==2{gsub(\"%\",\"\",$5); print $5}'")
    uptime, _ = run_cmd(client, "awk '{print int($1)}' /proc/uptime")

    return {
        "hostname": hostname or "unknown",
        "os_name": os_name or "Linux",
        "cpu": float(cpu or 0),
        "memory": float(memory or 0),
        "disk": float(disk or 0),
        "uptime_seconds": int(float(uptime or 0)),
        "services": collect_services(client),
    }


def collect_raw_logs(client, lines=120):
    entries = []
    journal, _ = run_cmd(client, f"journalctl -n {int(lines)} --no-pager -o short-iso 2>/dev/null", 15)
    for line in journal.splitlines():
        if line.strip():
            entries.append({"source": "journal", "line": line.strip()})

    for path, source in LOG_FILES:
        out, _ = run_cmd(client, f"if [ -r '{path}' ]; then tail -n 40 '{path}'; fi")
        for line in out.splitlines():
            if line.strip():
                entries.append({"source": source, "line": line.strip()})

    seen = set()
    unique = []
    for item in reversed(entries):
        key = item["source"] + "|" + item["line"]
        if key not in seen:
            seen.add(key)
            unique.append(item)
        if len(unique) >= 220:
            break
    return unique


def classify_log(line: str, source: str):
    low = line.lower()
    if "failed password" in low or "authentication failure" in low or "invalid user" in low:
        return "SSH_LOGIN_FAILED", "warning"
    if "accepted password" in low or "accepted publickey" in low:
        return "SSH_LOGIN_SUCCESS", "info"
    if source == "ids" or "suricata" in low or "[**]" in line:
        return "IDS_ALERT", "critical"
    if source == "web" and re.search(r'"\s+404\s+', line):
        return "HTTP_404", "warning"
    if "denied" in low or "blocked" in low or "drop" in low:
        return "ACCESS_DENIED", "warning"
    if "error" in low or "failed" in low:
        return "SYSTEM_ERROR", "warning"
    return "LOG", "info"


def store_events(system, logs):
    with get_db() as db:
        for item in logs[:120]:
            event_type, severity = classify_log(item["line"], item["source"])
            if event_type == "LOG":
                continue
            fingerprint = f'{system["id"]}|{item["source"]}|{item["line"]}'
            try:
                db.execute(
                    "INSERT INTO events(system_id,system_name,ip,occurred_at,type,severity,message,fingerprint) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        system["id"],
                        system["name"],
                        system["host"],
                        now_iso(),
                        event_type,
                        severity,
                        item["line"][:700],
                        fingerprint,
                    ),
                )
            except sqlite3.IntegrityError:
                pass


def system_to_dict(row):
    try:
        services = json.loads(row["services_json"] or "{}")
    except Exception:
        services = {}
    return {
        "id": row["id"],
        "name": row["name"],
        "host": row["host"],
        "port": row["port"],
        "username": row["username"],
        "status": row["status"],
        "os_name": row["os_name"],
        "hostname": row["hostname"],
        "last_seen": row["last_seen"],
        "last_error": row["last_error"],
        "cpu": row["cpu"],
        "memory": row["memory"],
        "disk": row["disk"],
        "uptime_seconds": row["uptime_seconds"],
        "services": services,
    }


def refresh_system(system_id: int):
    with get_db() as db:
        system = db.execute("SELECT * FROM systems WHERE id=?", (system_id,)).fetchone()
    if not system:
        return None

    try:
        client = ssh_client(system)
        try:
            metrics = collect_metrics(client)
            logs = collect_raw_logs(client)
        finally:
            client.close()

        status = "healthy"
        if metrics["cpu"] >= 90 or metrics["memory"] >= 90 or metrics["disk"] >= 90:
            status = "critical"
        elif metrics["cpu"] >= 75 or metrics["memory"] >= 80 or metrics["disk"] >= 80:
            status = "warning"

        with get_db() as db:
            db.execute(
                """
                UPDATE systems SET
                    status=?, os_name=?, hostname=?, last_seen=?, last_error='',
                    cpu=?, memory=?, disk=?, uptime_seconds=?, services_json=?
                WHERE id=?
                """,
                (
                    status,
                    metrics["os_name"],
                    metrics["hostname"],
                    now_iso(),
                    metrics["cpu"],
                    metrics["memory"],
                    metrics["disk"],
                    metrics["uptime_seconds"],
                    json.dumps(metrics["services"], ensure_ascii=False),
                    system_id,
                ),
            )
            updated = db.execute("SELECT * FROM systems WHERE id=?", (system_id,)).fetchone()

        store_events(updated, logs)
        return system_to_dict(updated)
    except Exception as exc:
        with get_db() as db:
            db.execute(
                "UPDATE systems SET status='offline', last_error=? WHERE id=?",
                (str(exc)[:500], system_id),
            )
        return {"id": system_id, "status": "offline", "error": str(exc)}


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/systems")
def api_systems():
    with get_db() as db:
        rows = db.execute("SELECT * FROM systems ORDER BY id").fetchall()
    return jsonify([system_to_dict(row) for row in rows])


@app.post("/api/systems")
def api_add_system():
    data = request.get_json(silent=True) or {}
    for key in ("host", "username", "password"):
        if not str(data.get(key, "")).strip():
            return jsonify({"error": f"필수값 누락: {key}"}), 400

    host = str(data["host"]).strip()
    username = str(data["username"]).strip()
    password = str(data["password"])
    port = int(data.get("port") or 22)
    name = str(data.get("name") or host).strip()
    temp = {"host": host, "port": port, "username": username, "password_enc": encrypt_password(password)}

    try:
        client = ssh_client(temp)
        detected_name, _ = run_cmd(client, "hostname")
        client.close()
    except Exception as exc:
        return jsonify({"error": f"SSH 연결 실패: {exc}"}), 400

    if not data.get("name") and detected_name:
        name = detected_name

    try:
        with get_db() as db:
            cur = db.execute(
                "INSERT INTO systems(name,host,port,username,password_enc,created_at) VALUES(?,?,?,?,?,?)",
                (name, host, port, username, temp["password_enc"], now_iso()),
            )
            system_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify({"error": "같은 IP/포트/사용자 시스템이 이미 등록되어 있습니다."}), 409

    return jsonify(refresh_system(system_id)), 201


@app.delete("/api/systems/<int:system_id>")
def api_delete_system(system_id):
    with get_db() as db:
        cur = db.execute("DELETE FROM systems WHERE id=?", (system_id,))
    if cur.rowcount == 0:
        return jsonify({"error": "시스템을 찾을 수 없습니다."}), 404
    return jsonify({"ok": True})


@app.post("/api/systems/<int:system_id>/refresh")
def api_refresh_system(system_id):
    result = refresh_system(system_id)
    if result is None:
        return jsonify({"error": "시스템을 찾을 수 없습니다."}), 404
    return jsonify(result)


@app.post("/api/refresh-all")
def api_refresh_all():
    with get_db() as db:
        ids = [r["id"] for r in db.execute("SELECT id FROM systems").fetchall()]
    return jsonify([refresh_system(i) for i in ids])


@app.get("/api/systems/<int:system_id>/logs")
def api_logs(system_id):
    with get_db() as db:
        system = db.execute("SELECT * FROM systems WHERE id=?", (system_id,)).fetchone()
    if not system:
        return jsonify({"error": "시스템을 찾을 수 없습니다."}), 404

    try:
        client = ssh_client(system)
        try:
            logs = collect_raw_logs(client, 160)
        finally:
            client.close()
        return jsonify({"system": system_to_dict(system), "logs": logs[:200]})
    except Exception as exc:
        return jsonify({"error": f"로그 조회 실패: {exc}"}), 500


@app.get("/api/events")
def api_events():
    severity = request.args.get("severity", "all")
    limit = min(max(int(request.args.get("limit", 200)), 1), 500)
    sql = "SELECT * FROM events"
    params = []
    if severity != "all":
        sql += " WHERE severity=?"
        params.append(severity)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_db() as db:
        rows = db.execute(sql, params).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/api/overview")
def api_overview():
    with get_db() as db:
        systems = db.execute("SELECT * FROM systems").fetchall()
        event_rows = db.execute("SELECT severity,COUNT(*) AS c FROM events GROUP BY severity").fetchall()
    counts = {"info": 0, "warning": 0, "critical": 0}
    for row in event_rows:
        counts[row["severity"]] = row["c"]
    return jsonify(
        {
            "total": len(systems),
            "healthy": sum(s["status"] == "healthy" for s in systems),
            "warning": sum(s["status"] == "warning" for s in systems),
            "critical": sum(s["status"] == "critical" for s in systems),
            "offline": sum(s["status"] == "offline" for s in systems),
            "event_counts": counts,
        }
    )


def background_refresh():
    while True:
        time.sleep(30)
        try:
            with get_db() as db:
                ids = [r["id"] for r in db.execute("SELECT id FROM systems").fetchall()]
            for system_id in ids:
                refresh_system(system_id)
        except Exception:
            pass


if __name__ == "__main__":
    init_db()
    FERNET = load_fernet()
    threading.Thread(target=background_refresh, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
else:
    init_db()
    FERNET = load_fernet()
