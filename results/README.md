# results/

파이프라인이 생성하는 모든 산출물이 모이는 디렉터리입니다. `.gitkeep`과
`snort_alerts.log.example`을 제외한 나머지는 실행할 때마다 생성되는 데이터라
`.gitignore`로 커밋 대상에서 제외되어 있습니다.

## 생성되는 파일 (누가 언제 만드는지)

| 파일 | 생성 주체 | 내용 |
|---|---|---|
| `<pcap_stem>_packets.csv` | `run.py analyze` | 패킷 단위 feature |
| `<pcap_stem>_host_stats.csv` | `run.py analyze` | src_ip별 집계 통계 |
| `compare_summary.csv` | `run.py analyze --compare` / `run.py compare` | 여러 pcap 비교 |
| `detection_result.csv` / `.json` | `run.py detect` | 위험도 점수·severity·breakdown (CSV는 append) |
| `alert.log` | `run.py detect` | playbook에 매칭된 액션이 있는 이벤트만 append |
| `notifications.log` | `run.py detect` / live 엔진 | playbook의 `notify` 액션 기록 (`source=offline`/`source=live`로 구분) |
| `graphs/*.png` | `run.py plot` | qname 길이/entropy/qtype 분포, risk score 막대그래프 |
| `siem_dns_detect.json` | live 엔진 | NDJSON, 한 줄이 하나의 탐지 이벤트 (매칭된 `actions` 포함) |
| `live_soar_state.db*` | live 엔진 | 차단 상태 SQLite (WAL). epoch 기준 TTL 저장 |
| `block_rules.log` | `scripts/block_ip.sh` / `unblock_ip.sh` | iptables 차단/해제 이력 |
| `snort_alerts.log` | Snort (`scripts/run_snort.sh`) | Snort fast alert 로그. `snort_alerts.log.example`은 형식 참고용 샘플이라 커밋되어 있음 |

## 정리

```bash
rm -f results/*.csv results/*.json results/*.log
rm -f results/*.db results/*.db-wal results/*.db-shm
rm -f results/graphs/*.png
```

자세한 내용은 루트 [README.md #19](../README.md#19-결과-파일-정리)를 참고하세요.
