# Live SOAR Engine

`engine/live_soar_engine.py`는 실시간 DNS 트래픽을 수집/분석/대응하는 방어용 엔진입니다.
전체 프로젝트 구조는 [루트 README](../README.md)를 참고하세요.

## 동작

- DNS 패킷 수집 (UDP/53), `process_packet`은 qname 정규화·src_ip 추출·기본형(dict) 큐잉만 수행
- 비동기 queue 기반 분석 (entropy, burst, 균일 간격, 블랙리스트 매칭) → severity(NORMAL/SUSPICIOUS/MALICIOUS/CRITICAL) 산출
- **[Playbook](../playbooks/dns_tunneling_response.yaml)** 이 severity에 맞는 액션(`block_ip`/`notify`/`log_only`)을 결정 → `ActionWorker`가 실행
- TTL 만료 시 자동 해제 (`unblock_ip.sh`)
- SIEM NDJSON 출력 (`results/siem_dns_detect.json`)

## 스레드 구성

| 스레드 | 역할 |
|---|---|
| `sniff()` (메인) | 패킷 캡처 → `packet_queue`에 primitive dict enqueue |
| `AnalysisWorker` | 위험도 계산 → severity 산출 → playbook 매칭 → `analysis_queue` / `action_queue`에 결과(및 매칭된 액션) enqueue |
| `ActionWorker` | playbook이 매칭한 액션 실행 (`block_ip`: iptables 차단 + 상태 DB 갱신, `notify`: `results/notifications.log` 기록) |
| `TTLScheduler` | 만료된 차단을 주기적으로 조회해 `unblock_ip.sh` 실행 |
| `NDJSONWriter` | 분석 결과를 NDJSON 파일에 append |

## Playbook (`playbooks/dns_tunneling_response.yaml`)

"CRITICAL이면 차단"처럼 조건→액션이 코드에 박혀 있지 않도록, 이 파일 하나를 offline
(`scripts/risk_engine.py`)과 live(`engine/live_soar_engine.py`)가 함께 읽습니다.
severity 판정 기준(`config/settings.yaml`의 `risk_levels`)과 조건→액션 매칭 로직은
`scripts/playbook.py`에만 구현되어 있고, 두 엔진은 이를 import해서 씁니다.

- severity 등급: `NORMAL < SUSPICIOUS < MALICIOUS < CRITICAL` (risk_score를 `risk_levels`
  임계값으로 변환)
- 각 규칙은 `when.min_severity`(해당 등급 이상이면 매칭)와 `actions`(실행할 액션 목록)로 구성
- 지원 액션: `block_ip`(iptables 차단, live는 즉시 실행 / offline은 `--block`+`--live`가 있어야
  실제 실행), `notify`(현재 `channel: log`만 지원, `results/notifications.log`에 append),
  `log_only`(별도 동작 없음)
- 조건 평가는 severity 등급 비교만 지원하며 `eval` 등 임의 코드 실행은 쓰지 않습니다.

대응 정책을 바꾸고 싶으면 코드가 아니라 이 YAML 파일만 수정하면 됩니다.

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
