# DNS 터널링 탐지·대응 시스템 (Snort + Scapy + Risk Engine + Live SOAR)

이 프로젝트는 VMware 실습망 기준으로 DNS 터널링을 **규칙 기반(Snort)** + **행위 기반(Scapy)** + **점수화 기반(Risk Engine)** 으로 탐지하고,
SIEM 로그 및 자동 대응(iptables/DNS sinkhole/blacklist)을 연결하는 통합 IDS/IPS 구조입니다.

## 필수 아키텍처

```text
DNS Packet Capture
→ Snort Rule Detection
→ Scapy Behavior Analysis
→ Risk Score Engine
→ SIEM Log
→ IP Blacklist / Domain Sinkhole / iptables Block
```

## 디렉터리 개요

- `run.py`: 통합 CLI
- `engine/live_soar_engine.py`: 실시간 DNS SOAR 엔진
- `engine/README.md`: live 엔진 사용/주의사항
- `scripts/dns_analyzer.py`: pcap 오프라인 분석
- `scripts/risk_engine.py`: 위험도 점수/판정
- `scripts/run_live_engine.sh`: live 엔진 실행 스크립트
- `rules/*.rules|*.txt`: Snort 규칙/blacklist/whitelist
- `config/settings.yaml`: 임계치/점수/대응 설정

## 빠른 시작

```bash
python run.py sample
python run.py analyze <pcap>
python run.py detect <pcap>
python run.py compare <normal_pcap> <attack_pcap>
python run.py plot <pcap>
sudo bash scripts/run_live_engine.sh
```

## Live SOAR 포인트

- `sniff(iface="any", filter="udp port 53", store=0)` 기반 실시간 수집
- queue 파이프라인 + oldest-drop 정책
- 위험도 CRITICAL 시 차단 연동(`block_ip.sh`)
- TTL 만료 시 자동 해제(`unblock_ip.sh`)
- SIEM NDJSON 저장: `results/siem_dns_detect.json`

## 안전/운영 원칙

- 본 저장소는 **방어(탐지/대응) 목적** 전용입니다.
- dnscat2 실행 자동화 및 공격 자동화 코드는 포함하지 않습니다.
- 차단 스크립트는 반드시 실습망에서만 사용하세요.
