# SecuView Live

샘플 데이터를 넣지 않은 **실제 IP 연결형** WAZUH 대체 대시보드입니다.
웹의 `+ 시스템 연결`에서 Linux 서버 IP/SSH 계정을 입력하면 Flask 백엔드가 SSH로 실제 CPU/RAM/Disk/서비스/로그를 읽습니다.

## 실행
Windows CMD/PowerShell에서 이 폴더로 이동 후:

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

브라우저에서:

```text
http://127.0.0.1:5000
```

## 서버 연결 조건
- 대상 Linux 서버의 SSH가 켜져 있어야 함
- 대시보드를 실행하는 PC에서 대상 IP로 통신 가능해야 함
- 웹에서 IP, Port(기본 22), 사용자, 비밀번호 입력
- root 또는 로그 읽기 권한이 있는 계정이면 더 많은 로그 표시 가능

예: DNS-Rocky
- IP: `192.168.16.117`
- Port: `22`
- User: `root`
- Password: 해당 VM의 root 비밀번호

## 실제 수집 정보
- hostname / OS
- CPU / RAM / Disk / uptime
- SSH / DNS / Web / DB / IDS 서비스 상태
- journalctl
- `/var/log/secure`, `/var/log/auth.log`
- Apache/httpd access/error log
- Suricata `fast.log` (있는 경우)

## 이벤트 자동 분류
- SSH 로그인 실패/성공
- IDS/Suricata 경고
- HTTP 404
- Access denied / blocked / drop
- system error / failed

## 저장
- `data/secuvue.db`: 시스템 메타데이터/이벤트
- `data/secret.key`: SSH 비밀번호 암호화용 로컬 키

브라우저가 직접 SSH를 하는 구조가 아니라 **중앙 Flask 백엔드가 SSH 연결을 담당**합니다.
학교 실습용이며 운영 환경에서는 SSH 키 인증, known_hosts 검증, HTTPS 사용을 권장합니다.
