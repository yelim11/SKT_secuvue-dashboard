from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

BASE_DIR = Path(__file__).resolve().parent\nPROJECT_DIR = BASE_DIR.parent
DB_PATH = Path(os.getenv("SECUVUE_DB_PATH", BASE_DIR / "secuvue.db"))
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
OFFLINE_AFTER_SECONDS = int(os.getenv("OFFLINE_AFTER_SECONDS", "90"))
CORS_ORIGINS = [x.strip() for x in os.getenv("CORS_ORIGINS", "*").split(",") if x.strip()]

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": CORS_ORIGINS}}, supports_credentials=False)

def utc_now():
    return datetime.now(timezone.utc)

def iso_now():
    return utc_now().isoformat(timespec="seconds")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS systems (
            agent_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            hostname TEXT NOT NULL,
            ip TEXT NOT NULL,
            os_name TEXT NOT NULL,
            cpu REAL NOT NULL DEFAULT 0,
            memory REAL NOT NULL DEFAULT 0,
            disk REAL NOT NULL DEFAULT 0,
            uptime_seconds INTEGER NOT NULL DEFAULT 0,
            services_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'offline',
            last_seen TEXT NOT NULL
        )""")
        db.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            agent_id TEXT NOT NULL,
            system_name TEXT NOT NULL,
            ip TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            source TEXT NOT NULL,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        )""")
init_db()

def auth_agent():
    if not AGENT_API_KEY:
        return jsonify({"error": "AGENT_API_KEY is not configured"}), 503
    if request.headers.get("X-API-Key", "") != AGENT_API_KEY:
        return jsonify({"error": "Invalid agent API key"}), 401
    return None

def auth_admin():
    if not ADMIN_API_KEY:
        return jsonify({"error": "ADMIN_API_KEY is not configured"}), 503
    if request.headers.get("X-Admin-Key", "") != ADMIN_API_KEY:
        return jsonify({"error": "Invalid admin key"}), 401
    return None

def status_from_metrics(cpu, memory, disk):
    if cpu >= 90 or memory >= 90 or disk >= 90:
        return "critical"
    if cpu >= 75 or memory >= 80 or disk >= 80:
        return "warning"
    return "healthy"

def parse_time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None

def row_to_system(row):
    data = dict(row)
    try:
        data["services"] = json.loads(data.pop("services_json") or "{}")
    except Exception:
        data["services"] = {}
    seen = parse_time(data.get("last_seen"))
    if seen and (utc_now() - seen.astimezone(timezone.utc)).total_seconds() > OFFLINE_AFTER_SECONDS:
        data["status"] = "offline"
    return data

@app.get("/")
def root():
    return jsonify({"service": "secuvue-api", "ok": True, "health": "/health"})

@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "secuvue-api", "time": iso_now()})

@app.get("/api/systems")
def systems():
    with get_db() as db:
        rows = db.execute("SELECT * FROM systems ORDER BY name COLLATE NOCASE").fetchall()
    return jsonify([row_to_system(r) for r in rows])

@app.post("/api/systems/register")
def register_system():
    err = auth_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    agent_id = str(data.get("agent_id", "")).strip()
    name = str(data.get("name", "")).strip()
    ip = str(data.get("ip", "")).strip()
    os_name = str(data.get("os_name", "")).strip() or "Waiting for agent"
    if not agent_id or not name or not ip:
        return jsonify({"error": "name, ip, agent_id are required"}), 400

    with get_db() as db:
        db.execute("""
        INSERT INTO systems
        (agent_id,name,hostname,ip,os_name,cpu,memory,disk,uptime_seconds,services_json,status,last_seen)
        VALUES(?,?,?,?,?,0,0,0,0,'{}','offline',?)
        ON CONFLICT(agent_id) DO UPDATE SET
          name=excluded.name,
          ip=excluded.ip,
          os_name=CASE WHEN systems.status='offline' THEN excluded.os_name ELSE systems.os_name END
        """, (agent_id, name, agent_id, ip, os_name, iso_now()))
        row = db.execute("SELECT * FROM systems WHERE agent_id=?", (agent_id,)).fetchone()
    return jsonify({"ok": True, "system": row_to_system(row)}), 201

@app.delete("/api/systems/<agent_id>")
def delete_system(agent_id):
    err = auth_admin()
    if err:
        return err
    with get_db() as db:
        db.execute("DELETE FROM events WHERE agent_id=?", (agent_id,))
        cur = db.execute("DELETE FROM systems WHERE agent_id=?", (agent_id,))
    if cur.rowcount == 0:
        return jsonify({"error": "System not found"}), 404
    return jsonify({"ok": True})

@app.get("/api/events")
def events():
    limit = min(max(int(request.args.get("limit", 200)), 1), 2000)
    severity = request.args.get("severity", "all")
    sql = "SELECT * FROM events"
    params = []
    if severity in {"info", "warning", "critical"}:
        sql += " WHERE severity=?"
        params.append(severity)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_db() as db:
        rows = db.execute(sql, params).fetchall()
    return jsonify([dict(r) for r in rows])

@app.get("/api/overview")
def overview():
    with get_db() as db:
        systems_rows = db.execute("SELECT * FROM systems").fetchall()
        event_rows = db.execute("SELECT severity,COUNT(*) c FROM events GROUP BY severity").fetchall()
    systems_data = [row_to_system(r) for r in systems_rows]
    counts = {"info": 0, "warning": 0, "critical": 0}
    for r in event_rows:
        counts[r["severity"]] = r["c"]
    return jsonify({
        "total": len(systems_data),
        "healthy": sum(x["status"] == "healthy" for x in systems_data),
        "warning": sum(x["status"] == "warning" for x in systems_data),
        "critical": sum(x["status"] == "critical" for x in systems_data),
        "offline": sum(x["status"] == "offline" for x in systems_data),
        "event_counts": counts,
    })

@app.post("/api/agent/status")
def agent_status():
    err = auth_agent()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    required = ["agent_id", "hostname", "ip", "os_name"]
    missing = [k for k in required if not str(data.get(k, "")).strip()]
    if missing:
        return jsonify({"error": "Missing fields: " + ", ".join(missing)}), 400

    agent_id = str(data["agent_id"]).strip()
    hostname = str(data["hostname"]).strip()
    ip = str(data["ip"]).strip()
    name = str(data.get("name") or hostname).strip()
    os_name = str(data["os_name"]).strip()
    cpu = float(data.get("cpu", 0))
    memory = float(data.get("memory", 0))
    disk = float(data.get("disk", 0))
    uptime = int(data.get("uptime_seconds", 0))
    services = data.get("services") or {}
    status = status_from_metrics(cpu, memory, disk)
    last_seen = iso_now()

    with get_db() as db:
        db.execute("""
        INSERT INTO systems
        (agent_id,name,hostname,ip,os_name,cpu,memory,disk,uptime_seconds,services_json,status,last_seen)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(agent_id) DO UPDATE SET
          name=excluded.name,hostname=excluded.hostname,ip=excluded.ip,os_name=excluded.os_name,
          cpu=excluded.cpu,memory=excluded.memory,disk=excluded.disk,uptime_seconds=excluded.uptime_seconds,
          services_json=excluded.services_json,status=excluded.status,last_seen=excluded.last_seen
        """, (agent_id,name,hostname,ip,os_name,cpu,memory,disk,uptime,json.dumps(services,ensure_ascii=False),status,last_seen))
    return jsonify({"ok": True, "status": status, "last_seen": last_seen})

@app.post("/api/agent/events")
def agent_events():
    err = auth_agent()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    agent_id = str(data.get("agent_id", "")).strip()
    system_name = str(data.get("system_name") or agent_id).strip()
    ip = str(data.get("ip", "")).strip()
    items = data.get("events") or []
    if not agent_id:
        return jsonify({"error": "agent_id is required"}), 400
    if not isinstance(items, list):
        return jsonify({"error": "events must be a list"}), 400

    inserted = 0
    with get_db() as db:
        for item in items[:500]:
            message = str(item.get("message", ""))[:1800]
            source = str(item.get("source", "system"))[:80]
            event_type = str(item.get("type", "LOG"))[:100]
            severity = str(item.get("severity", "info")).lower()
            if severity not in {"info","warning","critical"}:
                severity = "info"
            occurred_at = str(item.get("occurred_at") or iso_now())
            fingerprint = str(item.get("fingerprint") or "").strip()
            if not fingerprint:
                fingerprint = hashlib.sha256(f"{agent_id}|{source}|{message}".encode()).hexdigest()
            try:
                db.execute("""
                INSERT INTO events
                (fingerprint,agent_id,system_name,ip,occurred_at,source,type,severity,message)
                VALUES(?,?,?,?,?,?,?,?,?)
                """, (fingerprint,agent_id,system_name,ip,occurred_at,source,event_type,severity,message))
                inserted += 1
            except sqlite3.IntegrityError:
                pass
    return jsonify({"ok": True, "inserted": inserted})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
