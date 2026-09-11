# config/

프로젝트 전역 설정 파일 `settings.yaml` 하나만 둡니다. 탐지 임계치, 위험도 점수,
severity 등급 경계, blacklist/whitelist 경로, 차단·playbook 정책, live 엔진 설정을
전부 이 파일 한 곳에서 관리합니다.

## 파일

- `settings.yaml` — 아래 최상위 키를 가집니다. `schema.require_keys`에 나열된 키가
  없으면 `scripts/risk_engine.py`, `engine/live_soar_engine.py` 로딩 시 즉시 에러가 납니다.

| 키 | 역할 |
|---|---|
| `capture` | 캡처 인터페이스, pcap 저장 디렉터리 |
| `snort` | Snort 규칙 파일, alert 로그 경로 |
| `analysis` | 분석 시간 윈도우, 의심 도메인 |
| `thresholds` | entropy/qname 길이/qps 등 탐지 임계값 |
| `risk_scores` | 임계값 초과 시 부여되는 점수 (도메인/IP 블랙리스트 히트 포함) |
| `risk_levels` | `risk_score` → severity(NORMAL/SUSPICIOUS/MALICIOUS/CRITICAL) 경계값. offline/live 공용 |
| `blacklist` | 의심 도메인 목록, IP/도메인/화이트리스트 파일 경로 |
| `response` | 차단 모드/TTL, playbook YAML 경로(`playbook_path`) |
| `live` | live 엔진 인터페이스, BPF 필터, NDJSON/상태 DB 경로 |
| `schema` | 필수 최상위 키 목록 (검증용) |

값을 바꾸면 코드 재실행만으로 바로 반영됩니다(코드 수정 불필요). 자세한 설명은
루트 [README.md #7](../README.md#7-설정-configsettingsyaml)를 참고하세요.
