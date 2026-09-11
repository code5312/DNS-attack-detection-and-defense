# scripts/

offline 분석·위험도 판정·시각화·대응 스크립트를 모아둔 디렉터리입니다. 대부분
`run.py`를 통해 실행되지만, 개별 스크립트를 직접 호출할 수도 있습니다(더 많은
플래그를 제공하는 경우가 있습니다 — 예: `--playbook`, `--snort-log`).

## Python

| 파일 | 역할 | 직접 실행 예시 |
|---|---|---|
| `dns_analyzer.py` | pcap → DNS feature 추출(entropy, qtype, NXDOMAIN 등) + host별 통계 | `python scripts/dns_analyzer.py pcaps/normal_dns.pcap` |
| `risk_engine.py` | analyzer 결과 + Snort alert + 블랙리스트를 결합해 `risk_score`/severity 산출, playbook 매칭 | `python scripts/risk_engine.py pcaps/dnscat2_connect.pcap --block --playbook playbooks/tiered_response_example.yaml` |
| `playbook.py` | severity 판정(`severity_from_score`)과 playbook 매칭(`load_playbook`/`match_actions`) 공유 모듈. `risk_engine.py`와 `engine/live_soar_engine.py`가 함께 import — 이 파일에만 로직을 두고 두 엔진에서 각자 재구현하지 않습니다. | 직접 실행용 CLI는 없음 (라이브러리 모듈) |
| `plot_results.py` | 탐지 결과 시각화 (pcap 비교 그래프, `--csv`로 risk score 막대그래프) | `python scripts/plot_results.py --csv results/detection_result.csv` |
| `generate_sample_pcap.py` | 테스트용 정상/공격 유사 샘플 pcap 생성 (`run.py sample`이 호출) | `python scripts/generate_sample_pcap.py` |

## Shell

| 파일 | 역할 |
|---|---|
| `capture_dns.sh` | `tcpdump`로 UDP/53 트래픽을 `pcaps/`에 캡처 |
| `run_snort.sh` | pcap에 대해 Snort 실행, 결과를 `results/`에 저장 |
| `run_live_engine.sh` | `engine/live_soar_engine.py` 실행 래퍼 (`run.py live`와 동일) |
| `block_ip.sh` / `unblock_ip.sh` | iptables 차단/해제. IPv4 형식 검증 + `iptables -C`로 중복 규칙 방지, `results/block_rules.log`에 이력 기록 |
| `block_domain.sh` | dnsmasq sinkhole 설정 생성 (`/etc/dnsmasq.d/tunnel_block.conf`) |

## 안전 관련

- `dns_analyzer.py`, `risk_engine.py`, `playbook.py`는 pcap/설정 파일만 읽고 자체적으로
  차단을 수행하지 않습니다. 실제 차단은 `--block`(+`--live`) 플래그가 있을 때만,
  그리고 `block_ip.sh`를 통해서만 일어납니다.
- 코딩 제약(허용 패키지, live 엔진과의 역할 분리 등)은 [`../AGENTS.md`](../AGENTS.md)를 따릅니다.

전체 파이프라인 관점의 설명은 루트 [README.md](../README.md)를 참고하세요.
