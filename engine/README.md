# Live SOAR Engine

`engine/live_soar_engine.py`는 실시간 DNS 트래픽을 수집/분석/대응하는 방어용 엔진입니다.

## 동작
- DNS 패킷 수집 (UDP/53)
- 비동기 queue 기반 분석
- Risk score 계산
- CRITICAL 시 iptables 차단 연동
- TTL 만료 시 자동 해제
- SIEM NDJSON 출력 (`results/siem_dns_detect.json`)

## 실행
```bash
sudo bash scripts/run_live_engine.sh
```

## 주의
- 공격 자동화/외부 C2 연결 목적이 아닙니다.
- 반드시 실습망/격리망에서 사용하세요.
