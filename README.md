# DNS 터널링 탐지·대응 시스템 (dnscat2)

dnscat2 기반 DNS 터널링 공격을 **Snort 규칙 탐지**와 **Scapy 행위 분석**으로 병렬 탐지하고, 위험도 점수에 따라 경고·차단·도메인 sinkhole을 수행하는 실습/보고서용 프로젝트입니다.

## 프로젝트 목적

| 구분 | 역할 |
|------|------|
| **Snort** | UDP 53, `attacker.lab` 문자열, TXT/CNAME/MX 등 **명시적 패턴** 1차 탐지 |
| **Scapy** | qname 길이, Shannon entropy, QPS, qtype 분포 등 **통계적 이상행위** 분석 |
| **Risk Engine** | 두 결과를 통합해 내부 IP별 위험도 점수 산정 및 분류 |
| **대응** | 경고 로그, iptables 일시 차단, dnsmasq 도메인 sinkhole |

단일 탐지 방식의 한계를 보완하기 위해 **규칙 기반 + 행위 기반 + 점수화 대응**을 결합한 구조입니다.

## 탐지 아키텍처

```
[Ubuntu 피해자] DNS Query 발생
        ↓
[Sensor/Kali] DNS 패킷 수집 (tcpdump → pcaps/)
        ↓
 ┌──────────────────────┬─────────────────────────┐
 │ Snort Rule Engine    │ Scapy Analyzer           │
 │ - UDP 53             │ - qname/qtype/src IP     │
 │ - attacker.lab       │ - qname 길이, entropy    │
 │ - TXT/CNAME/MX       │ - QPS, qtype 분포        │
 └──────────────────────┴─────────────────────────┘
        ↓
 Risk Score Aggregation (내부 IP별)
        ↓
 임계치 판단 ([LOW] / [MEDIUM] / [HIGH])
        ↓
 대응: 경고 로그 | iptables 차단 | 도메인 sinkhole
```

> **설계 참고:** qname 길이 검사는 Snort에서 구현이 제한적이므로 **Scapy**에서 수행합니다.

## 디렉터리 구조

```
dns_detection/
├── config/
│   └── settings.yaml          # 임계치, 위험도 점수, 차단 모드
├── pcaps/                     # 수집 pcap (normal_dns, dnscat2_*)
├── rules/
│   ├── dns_tunnel.rules       # Snort 룰
│   └── dnsmasq_sinkhole.conf  # 도메인 차단 정책
├── scripts/
│   ├── dns_analyzer.py        # Scapy 분석 (핵심)
│   ├── risk_engine.py         # 위험도 점수 + verdict
│   ├── plot_results.py        # matplotlib 시각화
│   ├── block_ip.sh            # iptables 차단
│   ├── unblock_ip.sh          # iptables 해제
│   ├── block_domain.sh        # dnsmasq sinkhole
│   ├── capture_dns.sh         # tcpdump 수집
│   ├── generate_sample_pcap.py
│   └── run_snort.sh           # Snort 실행 안내
├── results/
│   ├── *_packets.csv          # 패킷 단위 분석
│   ├── *_host_stats.csv       # IP별 통계
│   ├── detection_result.csv   # 탐지 결과
│   ├── detection_result.json
│   ├── alert.log
│   └── graphs/                # 시각화 출력
├── run.py                     # 통합 CLI
├── requirements.txt
├── venv/                      # 가상환경 (로컬 생성)
└── README.md
```

## 환경 설정

### 요구 사항

- Python 3.10+
- 실습 VM: Ubuntu(피해자), Kali(dnscat2 서버/Sensor)
- 선택: Snort, tcpdump, iptables, dnsmasq

### 가상환경 (권장)

```powershell
# Windows
cd dns_detection
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

```bash
# Linux (Ubuntu/Kali)
cd dns_detection
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 빠른 시작

```bash
# 1) 테스트용 샘플 pcap 생성
python run.py sample

# 2) 정상 DNS 분석
python run.py analyze pcaps/normal_dns.pcap

# 3) 공격 DNS 분석
python run.py analyze pcaps/dnscat2_connect.pcap

# 4) 정상 vs 공격 비교
python run.py compare pcaps/normal_dns.pcap pcaps/dnscat2_connect.pcap

# 5) 위험도 판단 + 로그 저장
python run.py detect pcaps/dnscat2_connect.pcap

# 6) 그래프 생성 (선택)
python run.py plot pcaps/normal_dns.pcap pcaps/dnscat2_connect.pcap

# 7) HIGH verdict 시 iptables 차단 (Linux, sudo 필요)
python run.py detect pcaps/dnscat2_connect.pcap --block --live
```

## CLI 명령어 (`run.py`)

| 명령 | 설명 |
|------|------|
| `python run.py sample` | 샘플 pcap 생성 (`normal_dns`, `dnscat2_connect`) |
| `python run.py analyze <pcap>` | Scapy 분석 → CSV 저장 |
| `python run.py compare <pcap1> <pcap2>` | 정상 vs 공격 비교 CSV |
| `python run.py detect <pcap>` | 위험도 점수 + verdict + 로그 |
| `python run.py detect <pcap> --block --live` | HIGH 시 iptables 실제 차단 |
| `python run.py plot <pcap> ...` | qname 길이/entropy/qtype 그래프 |

개별 스크립트도 직접 실행할 수 있습니다.

```bash
python scripts/dns_analyzer.py pcaps/dnscat2_connect.pcap
python scripts/risk_engine.py pcaps/dnscat2_connect.pcap --block
```

## 실습 흐름 (권장)

1. **트래픽 수집** — Sensor/Kali에서 tcpdump
   ```bash
   sudo bash scripts/capture_dns.sh eth0 normal_dns
   sudo bash scripts/capture_dns.sh eth0 dnscat2_connect
   ```
2. **분석** — `dns_analyzer.py`로 특징 추출
3. **비교** — 정상 vs dnscat2 (길이, entropy, qtype)
4. **탐지** — `risk_engine.py`로 위험도·verdict
5. **대응** — 임계치 초과 시 `block_ip.sh` 실행
6. **검증** — Wireshark/dnscat2 세션 종료 확인

### 수집 pcap 권장 파일명

| 파일 | 설명 |
|------|------|
| `normal_dns.pcap` | 정상 DNS |
| `dnscat2_connect.pcap` | C2 연결 |
| `dnscat2_shell.pcap` | 셸 세션 |
| `dnscat2_exec.pcap` | 명령 실행 |
| `dnscat2_upload.pcap` | 업로드 |
| `dnscat2_download.pcap` | 다운로드 |

## 핵심 모듈

### `scripts/dns_analyzer.py` (1순위)

- pcap에서 DNS Query 추출: `qname`, `qtype`, `src_ip`, `timestamp`
- **Shannon entropy** 직접 구현 (`shannon_entropy()`)
- qname/subdomain 길이, qtype 분포, QPS, unique qname
- 내부 IP별 통계 → `results/{pcap}_packets.csv`, `{pcap}_host_stats.csv`

### `scripts/risk_engine.py` (2순위)

내부 IP별 위험도 점수 예시:

| 조건 | 점수 |
|------|------|
| 평균 qname 길이 > 50 | +2 |
| 최대 qname 길이 > 80 | +2 |
| 평균 entropy > 3.5 | +2 |
| 분당 query > 100 | +3 |
| TXT/CNAME/MX 비율 > 50% | +2 |
| 동일 base domain 반복 > 30 | +2 |
| Snort alert | +3 (건당) |
| attacker.lab 포함 | +2 |

**Verdict 분류** (`config/settings.yaml`):

| 점수 | 등급 | 의미 |
|------|------|------|
| 0~3 | `[LOW]` | 정상 DNS |
| 4~6 | `[MEDIUM]` | 의심 DNS 터널링 가능성 |
| 7+ | `[HIGH]` | DNS 터널링 의심, 차단 권고 |

### `rules/dns_tunnel.rules` (Snort)

- `attacker.lab` 문자열, TXT/CNAME/MX, 긴 DNS payload 등
- pcap 테스트: `scripts/run_snort.sh` 참고
- Alert 로그: `results/snort_alerts.log` (Python 분석과 통합)

## 대응 (Response)

### iptables 차단 (`scripts/block_ip.sh`)

차단 **위치**에 따라 명령이 달라집니다. 보고서에 반드시 명시하세요.

| 모드 | 위치 | 명령 개념 |
|------|------|-----------|
| `kali_input` (기본) | Kali 서버 | 피해자 IP → Kali UDP/53 DROP |
| `ubuntu_output` | Ubuntu 로컬 | 자신의 DNS 송신 차단 |
| `gateway_forward` | 게이트웨이/Sensor | FORWARD 체인 차단 |

```bash
# Kali에서 Ubuntu(172.30.1.44) 차단 (실습 권장)
sudo bash scripts/block_ip.sh 172.30.1.44 kali_input

# 해제
sudo bash scripts/unblock_ip.sh 172.30.1.44 kali_input
```

기본은 **dry-run**입니다. 실제 차단: `python run.py detect <pcap> --block --live`

### 도메인 sinkhole (`rules/dnsmasq_sinkhole.conf`)

```
address=/attacker.lab/0.0.0.0
```

- `./dnscat attacker.lab` 방식 → 도메인 차단 효과 **큼**
- `./dnscat --dns server=172.30.1.21` 직접 IP 지정 → 도메인 차단만으로 **부족**, UDP/53 차단 필요

```bash
sudo bash scripts/block_domain.sh attacker.lab
```

## 출력 파일

| 파일 | 내용 |
|------|------|
| `results/*_packets.csv` | 패킷별 qname, qtype, entropy, 길이 |
| `results/*_host_stats.csv` | IP별 통계 요약 |
| `results/detection_result.csv` | 탐지 결과 (risk_score, verdict) |
| `results/detection_result.json` | JSON 형식 동일 데이터 |
| `results/alert.log` | MEDIUM/HIGH 경고 |
| `results/compare_summary.csv` | 정상 vs 공격 비교 |
| `results/graphs/*.png` | 시각화 그래프 |

**CSV 예시 (detection_result.csv):**

```csv
timestamp,pcap,src_ip,avg_entropy,avg_qname_len,query_count,txt_cname_ratio,snort_alerts,risk_score,verdict_level,verdict,action
```

## 설정 (`config/settings.yaml`)

- `thresholds` — 점수 부여 기준값
- `risk_scores` — 조건별 가산 점수
- `risk_levels` — LOW/MEDIUM/HIGH 경계
- `response.block_mode` — iptables 차단 모드 (`kali_input` 등)
- `snort.alert_log` — Snort alert 로그 경로

Snort alert를 반영하려면 `results/snort_alerts.log`를 준비하세요. 예시: `results/snort_alerts.log.example`

## 운영 흐름 (실무형)

```
탐지 → 위험도 산정 → 경고 → 임계치 초과 시 IP 차단 → 로그 기록 → 관리자 후속 확인
```

단일 Snort 룰 매칭만으로 즉시 차단하지 않고, **복합 위험도 임계치**를 거친 뒤 차단하여 오탐을 줄입니다.

## 의존성

```
scapy>=2.5.0
pyyaml>=6.0
matplotlib>=3.7.0
```

## 참고

> 본 프로젝트의 탐지 구조는 Snort 기반의 규칙 탐지와 Scapy 기반의 행위 분석을 병렬적으로 수행한다. Snort는 UDP 53번 포트, 특정 공격 도메인 문자열, TXT/CNAME/MX와 같은 의심 qtype을 빠르게 탐지하는 1차 필터 역할을 수행한다. Scapy 기반 분석기는 DNSQR 계층의 qname과 qtype을 추출하여 qname 길이, Shannon entropy, 초당 질의 수, 내부 IP별 반복 질의 횟수 등을 계산한다. 이후 두 탐지 결과를 통합하여 내부 IP별 위험도 점수를 산정하고, 임계치를 초과한 경우 경고 출력, iptables 기반 일시 차단, 공격 도메인 sinkhole 등의 대응을 수행한다.

---

dnscat2 DNS 터널링 탐지·대응 프로젝트
