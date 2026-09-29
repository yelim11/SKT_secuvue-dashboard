# SecuView Dashboard

팀 과제용 **WAZUH 대체 보안 모니터링 웹 애플리케이션**입니다.

이 저장소는 GitHub Pages 정적 프론트엔드와 Render API, 각 Linux 서버에 설치하는 Agent를 분리한 구조입니다.

```text
Linux Server (DNS / Web-DB / Ubuntu / Rocky ...)
        │
        │ HTTPS POST (실제 CPU/RAM/Disk/로그)
        ▼
Render : backend/
        │
        │ REST API
        ▼
GitHub Pages : index.html + css/ + js/
```

## 왜 이 구조인가?

팀 서버의 IP가 `192.168.x.x` 같은 사설 IP이면 인터넷의 Render 서버가 그 IP로 직접 SSH 접속할 수 없습니다.

그래서 각 서버에서 `agent/agent.py`를 실행해 **서버가 자신의 실제 상태와 로그를 Render로 보내는 방식**으로 구성합니다. GitHub Pages는 Render API에서 데이터를 읽어서 대시보드에 표시합니다.

---

## 저장소 구조

```text
SKT_secuvue-dashboard/
├─ index.html             # GitHub Pages
├─ css/style.css
├─ js/app.js
├─ .nojekyll
├─ backend/
│  ├─ app.py              # Render API
│  └─ requirements.txt
├─ agent/
│  ├─ agent.py            # 각 Linux 서버에서 실행
│  ├─ config.example.env
│  └─ secuvue-agent.service
├─ render.yaml
└─ README.md
```

---

# 1. GitHub Pages 배포

GitHub 저장소에서:

1. `Settings`
2. `Pages`
3. `Build and deployment`
4. Source → `Deploy from a branch`
5. Branch → `main`
6. Folder → `/ (root)`
7. `Save`

배포 주소는 보통:

```text
https://yelim11.github.io/SKT_secuvue-dashboard/
```

처음에는 Backend API가 설정되지 않았다는 안내가 정상적으로 표시됩니다.

---

# 2. Render Backend 배포

이 저장소에는 `render.yaml`이 포함되어 있습니다.

Render에서:

1. `New +`
2. `Blueprint`
3. GitHub의 `SKT_secuvue-dashboard` 저장소 연결
4. Blueprint 적용
5. `secuvue-api` 서비스 생성 확인

`render.yaml` 기준:

```text
Root Directory : backend
Build Command  : pip install -r requirements.txt
Start Command  : gunicorn app:app
Health Check   : /health
```

Render 환경변수에서 생성된 `AGENT_API_KEY` 값을 확인합니다.

> 이 키는 GitHub에 올리지 말고 팀원에게 별도로 전달하세요.

배포가 완료되면 예:

```text
https://secuvue-api.onrender.com
```

이 주소의 `/health`가 다음처럼 응답하면 정상입니다.

```json
{"ok": true, "service": "secuvue-api"}
```

---

# 3. GitHub Pages에서 Render 연결

배포된 SecuView 페이지를 열고:

`API 설정` → Render URL 입력 → `연결 테스트 후 저장`

예:

```text
https://secuvue-api.onrender.com
```

브라우저 localStorage에만 저장되기 때문에 Render 주소를 소스코드에 하드코딩할 필요가 없습니다.

---

# 4. Linux 서버에 Agent 설치

예: DNS-Rocky.

먼저 필요한 파일을 서버에 준비합니다.

```bash
sudo mkdir -p /opt/secuvue-agent
sudo cp agent.py /opt/secuvue-agent/agent.py
sudo chmod 755 /opt/secuvue-agent/agent.py
```

환경 설정:

```bash
sudo vi /etc/secuvue-agent.env
```

예:

```text
SECUVUE_API_URL=https://secuvue-api.onrender.com
SECUVUE_API_KEY=Render에서_확인한_AGENT_API_KEY
SECUVUE_AGENT_ID=dns-rocky
SECUVUE_AGENT_NAME=DNS-Rocky
SECUVUE_INTERVAL=30
```

먼저 한 번 테스트:

```bash
set -a
source /etc/secuvue-agent.env
set +a
sudo -E python3 /opt/secuvue-agent/agent.py --once
```

정상이면:

```text
[OK] status -> DNS-Rocky / healthy
```

처럼 표시됩니다.

---

# 5. Agent 자동 실행

`agent/secuvue-agent.service`를 `/etc/systemd/system/`에 복사:

```bash
sudo cp secuvue-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now secuvue-agent
sudo systemctl status secuvue-agent
```

Agent 상태 확인:

```bash
journalctl -u secuvue-agent -f
```

---

# 실제 수집 데이터

Agent가 각 Linux 서버에서 실제로 수집합니다.

- hostname
- IP
- OS
- CPU 사용률
- RAM 사용률
- Disk 사용률
- Uptime
- SSH 상태
- DNS(named/bind9) 상태
- Apache/httpd/nginx 상태
- MariaDB/MySQL 상태
- Suricata/Snort 상태

로그가 존재하고 읽을 수 있을 경우:

- `/var/log/secure`
- `/var/log/auth.log`
- Apache/httpd access/error log
- Suricata `fast.log`
- `journalctl`

---

# 보안 이벤트 분류

현재 Agent는 다음 이벤트를 자동 분류합니다.

| 이벤트 | 위험도 |
|---|---|
| SSH 로그인 성공 | Info |
| SSH 로그인 실패 / Invalid user | Warning |
| HTTP 404 | Warning |
| Access denied / blocked / drop | Warning |
| 시스템 오류 | Warning |
| Suricata/IDS Alert | Critical |

---

# Kali 테스트 예시

팀 실습망에서 Kali로 서버에 잘못된 SSH 로그인을 발생시키거나 웹 경로를 요청하면 서버 로그에 기록됩니다.

그 로그를 Agent가 읽어서:

```text
Linux Server → Render API → GitHub Pages
```

순서로 전달하고 SecuView의 `Events` 화면에서 확인할 수 있습니다.

---

# 주의사항

- `AGENT_API_KEY`는 GitHub에 커밋하지 않습니다.
- 서버 비밀번호를 웹사이트에 저장하지 않습니다.
- GitHub Pages에는 서버 접속 비밀번호나 API 쓰기 키가 포함되지 않습니다.
- 현재 SQLite DB는 Render 인스턴스 파일시스템에 저장되므로 재배포/재시작 시 데이터가 초기화될 수 있습니다.
  과제 최종 단계에서 영구 보존이 필요하면 PostgreSQL/Supabase로 교체할 수 있습니다.
- 이 프로젝트는 수업용/실습용입니다.
