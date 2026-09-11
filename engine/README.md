# Live SOAR Engine

`engine/live_soar_engine.py`는 실시간 DNS 트래픽을 수집/분석/대응하는 방어용 엔진입니다.
전체 프로젝트 구조는 [루트 README](../README.md)를 참고하세요.

## 동작

- DNS 패킷 수집 (UDP/53), `process_packet`은 qname 정규화·src_ip 추출·기본형(dict) 큐잉만 수행
- 비동기 queue 기반 분석 (entropy, burst, 균일 간격, 블랙리스트 매칭)
- Risk score 계산 → CRITICAL 시 iptables 차단 연동 (`block_ip.sh`)
- TTL 만료 시 자동 해제 (`unblock_ip.sh`)
- SIEM NDJSON 출력 (`results/siem_dns_detect.json`)

## 스레드 구성

| 스레드 | 역할 |
|---|---|
| `sniff()` (메인) | 패킷 캡처 → `packet_queue`에 primitive dict enqueue |
| `AnalysisWorker` | 위험도 계산 → `analysis_queue` / `webhook_queue`에 결과 enqueue |
| `WebhookWorker` | CRITICAL 알림 처리, `block_ip.sh` 실행, 상태 DB 갱신 |
| `TTLScheduler` | 만료된 차단을 주기적으로 조회해 `unblock_ip.sh` 실행 |
| `NDJSONWriter` | 분석 결과를 NDJSON 파일에 append |

## 상태 저장 (`results/live_soar_state.db`)

차단 상태와 TTL 만료 시각은 SQLite에 **벽시계(epoch, `time.time()`) 기준**으로 저장됩니다.
`time.monotonic()`은 프로세스/부팅마다 기준점이 달라지므로 재시작 후에도 유효한 값이 필요한
영속 데이터에는 사용하지 않습니다. 구버전 스키마(`unblock_at_mono`)로 만들어진 DB는 기동 시
자동으로 감지되어 정리(재생성)됩니다.

## 실행

```bash
sudo bash scripts/run_live_engine.sh
```

## 주의

- 공격 자동화/외부 C2 연결 목적이 아닙니다.
- 반드시 실습망/격리망에서 사용하세요.
- 세부 코딩 제약은 [`../AGENTS.md`](../AGENTS.md)의 "Live Engine Rules"를 따릅니다.
