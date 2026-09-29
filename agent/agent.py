#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SERVICE_GROUPS = {
    "SSH": ["sshd", "ssh"],
    "DNS": ["named", "bind9"],
    "Web": ["httpd", "apache2", "nginx"],
    "DB": ["mariadb", "mysql", "mysqld"],
    "IDS": ["suricata", "snort3", "snort"],
}

LOG_FILES = [
    ("/var/log/secure", "auth"),
    ("/var/log/auth.log", "auth"),
    ("/var/log/httpd/access_log", "web"),
    ("/var/log/httpd/error_log", "web"),
    ("/var/log/apache2/access.log", "web"),
    ("/var/log/apache2/error.log", "web"),
    ("/var/log/suricata/fast.log", "ids"),
]


def utc_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run(command):
    try:
        return subprocess.check_output(
            command,
            shell=True,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        ).strip()
    except Exception:
        return ""


def local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def os_name():
    try:
        data = {}
        for line in Path("/etc/os-release").read_text(errors="ignore").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value.strip().strip('"')
        return data.get("PRETTY_NAME") or platform.platform()
    except Exception:
        return platform.platform()


def cpu_percent():
    def read_cpu():
        fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
        values = [int(x) for x in fields[:8]]
        idle = values[3] + values[4]
        total = sum(values)
        return idle, total

    try:
        idle1, total1 = read_cpu()
        time.sleep(0.25)
        idle2, total2 = read_cpu()
        total_delta = total2 - total1
        idle_delta = idle2 - idle1
        if total_delta <= 0:
            return 0.0
        return round((total_delta - idle_delta) * 100 / total_delta, 1)
    except Exception:
        return 0.0


def memory_percent():
    values = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            values[key] = int(value.strip().split()[0])
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", 0)
        return round((total - available) * 100 / total, 1) if total else 0.0
    except Exception:
        return 0.0


def disk_percent():
    usage = shutil.disk_usage("/")
    return round(usage.used * 100 / usage.total, 1) if usage.total else 0.0


def uptime_seconds():
    try:
        return int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        return 0


def service_status():
    result = {}
    for label, candidates in SERVICE_GROUPS.items():
        state = "not-found"
        matched = ""
        for service in candidates:
            active = run(f"systemctl is-active {service}")
            if active == "active":
                state = "active"
                matched = service
                break

            exists = run(
                f"systemctl list-unit-files --type=service | grep -q '^{service}\\\\.service' && echo yes"
            )
            if exists == "yes":
                state = "inactive"
                matched = service
                break

        result[label] = {"service": matched, "state": state}
    return result


def classify(line, source):
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

    return None


def read_interesting_logs(max_lines=80):
    candidates = []

    journal = run(f"journalctl -n {max_lines} --no-pager -o short-iso")
    for line in journal.splitlines():
        if line.strip():
            candidates.append(("journal", line.strip()))

    for path, source in LOG_FILES:
        file_path = Path(path)
        if not file_path.is_file() or not os.access(file_path, os.R_OK):
            continue
        try:
            lines = file_path.read_text(errors="replace").splitlines()[-40:]
            for line in lines:
                if line.strip():
                    candidates.append((source, line.strip()))
        except Exception:
            pass

    events = []
    for source, line in candidates:
        classified = classify(line, source)
        if not classified:
            continue

        event_type, severity = classified
        fingerprint = hashlib.sha256(f"{source}|{line}".encode()).hexdigest()
        events.append(
            {
                "fingerprint": fingerprint,
                "occurred_at": utc_iso(),
                "source": source,
                "type": event_type,
                "severity": severity,
                "message": line[:1500],
            }
        )

    unique = {}
    for event in events:
        unique[event["fingerprint"]] = event
    return list(unique.values())[-200:]


def post_json(api_base, path, api_key, payload):
    body = json.dumps(payload, ensure_ascii=False).encode()
    request = urllib.request.Request(
        f"{api_base.rstrip('/')}{path}",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "User-Agent": "SecuView-Agent/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        return json.loads(response.read().decode())


def collect_payload(agent_id, name):
    hostname = socket.gethostname()
    return {
        "agent_id": agent_id,
        "name": name or hostname,
        "hostname": hostname,
        "ip": local_ip(),
        "os_name": os_name(),
        "cpu": cpu_percent(),
        "memory": memory_percent(),
        "disk": disk_percent(),
        "uptime_seconds": uptime_seconds(),
        "services": service_status(),
    }


def send_once(api_base, api_key, agent_id, name):
    status = collect_payload(agent_id, name)
    result = post_json(api_base, "/api/agent/status", api_key, status)
    print(f"[OK] status -> {status['name']} / {result.get('status')}")

    events = read_interesting_logs()
    if events:
        result = post_json(
            api_base,
            "/api/agent/events",
            api_key,
            {
                "agent_id": agent_id,
                "system_name": status["name"],
                "ip": status["ip"],
                "events": events,
            },
        )
        print(f"[OK] events -> inserted {result.get('inserted', 0)}")


def parse_args():
    parser = argparse.ArgumentParser(description="SecuView Linux Agent")
    parser.add_argument("--api", default=os.getenv("SECUVUE_API_URL", ""))
    parser.add_argument("--key", default=os.getenv("SECUVUE_API_KEY", ""))
    parser.add_argument("--id", default=os.getenv("SECUVUE_AGENT_ID", socket.gethostname()))
    parser.add_argument("--name", default=os.getenv("SECUVUE_AGENT_NAME", ""))
    parser.add_argument("--interval", type=int, default=int(os.getenv("SECUVUE_INTERVAL", "30")))
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.api:
        raise SystemExit("SECUVUE_API_URL 또는 --api 값을 지정하세요.")
    if not args.key:
        raise SystemExit("SECUVUE_API_KEY 또는 --key 값을 지정하세요.")

    while True:
        try:
            send_once(args.api, args.key, args.id, args.name)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            print(f"[ERROR] HTTP {exc.code}: {body}")
        except Exception as exc:
            print(f"[ERROR] {exc}")

        if args.once:
            break
        time.sleep(max(args.interval, 10))


if __name__ == "__main__":
    main()
