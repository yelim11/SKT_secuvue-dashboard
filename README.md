# SecuView Dashboard

팀 과제용 **WAZUH 스타일 보안 모니터링 웹 애플리케이션**입니다.  
Wazuh의 대시보드 흐름을 참고했지만 브랜드와 코드는 SecuView 자체 구현입니다.

## 현재 기능

- Wazuh 스타일 Dashboard / Agents / Events 화면
- Total alerts / Critical / SSH 인증 성공·실패 요약
- 시간대별 Alert 추이
- 공격 유형(MITRE ATT&CK 형태) 분류
- Top agents / 시스템별 이벤트 수
- 최근 Security Alerts
- 시간 범위 / 검색 / 위험도 / Agent / 이벤트 유형 필터
- CSV Report 생성
- 시스템 이름 + IP + Agent ID 등록
- Agent 상세 화면: IP, OS, CPU, RAM, Disk, 서비스, Last seen, 최근 이벤트
- Agent heartbeat가 90초 이상 없으면 Disconnected 처리
- 실제 Linux Agent가 Render API로 시스템 상태와 로그 전송

## 구조

```text
GitHub Pages (SecuView UI)
        │
        │ REST API
        ▼
Render Flask API
        ▲
        │ HTTPS POST
        │
Linux Agent
DNS / Web-DB / Ubuntu / Rocky ...
```

> `192.168.x.x` 같은 사설 IP는 Render가 인터넷에서 직접 SSH 접속할 수 없습니다.
> 그래서 웹에서 IP/Agent ID를 등록한 뒤 해당 서버의 Agent가 실제 정보를 Render로 전송합니다.

## 1. GitHub Pages

저장소의 `Settings → Pages`에서:

```text
Source : Deploy from a branch
Branch : main
Folder : / (root)
```

페이지:

```text
https://yelim11.github.io/SKT_secuvue-dashboard/
```

## 2. Render Backend

`render.yaml`을 이용해 Blueprint로 배포합니다.

필수 환경변수:

- `AGENT_API_KEY`: Linux Agent가 데이터를 전송할 때 사용하는 키
- `ADMIN_API_KEY`: 웹에서 시스템을 등록할 때 사용하는 관리자 키
- `CORS_ORIGINS=https://yelim11.github.io`
- `OFFLINE_AFTER_SECONDS=90`

정상 확인:

```text
https://YOUR-SERVICE.onrender.com/health
```

## 3. 웹에서 API 연결

SecuView 우측 상단 ⚙ 버튼:

```text
Backend API URL : https://YOUR-SERVICE.onrender.com
Admin Key       : Render의 ADMIN_API_KEY
```

`연결 테스트 후 저장`을 누릅니다.

## 4. 시스템 등록

`+ Add system`에서 예:

```text
System name : DNS-Rocky
IP address  : 192.168.16.117
Agent ID    : dns-rocky
OS          : Rocky Linux
```

등록 직후에는 **Disconnected**가 정상입니다.  
대상 서버의 Agent가 heartbeat를 보내면 실제 시스템 정보로 갱신됩니다.

## 5. Linux Agent 설치

```bash
sudo mkdir -p /opt/secuvue-agent
sudo cp agent/agent.py /opt/secuvue-agent/agent.py
sudo chmod 755 /opt/secuvue-agent/agent.py
sudo vi /etc/secuvue-agent.env
```

예:

```text
SECUVUE_API_URL=https://YOUR-SERVICE.onrender.com
SECUVUE_API_KEY=Render의_AGENT_API_KEY
SECUVUE_AGENT_ID=dns-rocky
SECUVUE_AGENT_NAME=DNS-Rocky
SECUVUE_INTERVAL=30
```

1회 테스트:

```bash
set -a
source /etc/secuvue-agent.env
set +a
sudo -E python3 /opt/secuvue-agent/agent.py --once
```

자동 실행:

```bash
sudo cp agent/secuvue-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now secuvue-agent
sudo systemctl status secuvue-agent
```

## 실제 수집 정보

- hostname / IP / OS
- CPU / RAM / Disk / uptime
- SSH
- DNS(named/bind9)
- Apache/httpd/nginx
- MariaDB/MySQL
- Suricata/Snort
- journalctl
- /var/log/secure
- /var/log/auth.log
- Apache/httpd access/error log
- Suricata fast.log

## 보안 이벤트 분류

| 이벤트 | 표시 |
|---|---|
| SSH 로그인 성공 | Info / Valid Accounts |
| SSH 로그인 실패 | Warning / Password Guessing |
| HTTP 404 | Warning / Web Attack |
| Access denied / blocked / drop | Warning |
| 시스템 오류 | Warning |
| Suricata / IDS Alert | Critical |

## 주의

- `AGENT_API_KEY`, `ADMIN_API_KEY`는 GitHub에 커밋하지 않습니다.
- 서버 SSH 비밀번호는 웹페이지에 저장하지 않습니다.
- Admin Key는 사용자가 직접 입력하며 브라우저 localStorage에만 저장됩니다.
- 현재 DB는 SQLite이므로 Render 무료 인스턴스 재배포/재시작 시 데이터가 유지되지 않을 수 있습니다.
