# rules/

Snort 탐지 규칙과 IP/도메인 정책 파일을 모아둔 디렉터리입니다. 전부 텍스트라
git에 그대로 커밋됩니다.

## 파일

| 파일 | 역할 |
|---|---|
| `dns_tunnel.rules` | Snort 1차 탐지 규칙 (attacker.lab 문자열, 긴 payload, Base32/HEX-like 라벨, 랜덤 서브도메인, TXT/CNAME/MX heuristic). `scripts/run_snort.sh`가 사용하고, 매칭된 sid는 `scripts/risk_engine.py`의 `snort_sid_allow`에 등록된 것만 위험도에 반영됩니다. |
| `ip_blacklist.txt` | 차단 대상 IPv4, 한 줄에 하나. offline(`risk_engine.py`)과 live 엔진이 모두 읽습니다. |
| `domain_blacklist.txt` | 차단 대상 base domain, 한 줄에 하나. |
| `domain_whitelist.txt` | 예외 도메인. 매칭되면 severity가 NORMAL로 처리되어 위험도 계산에서 제외됩니다. |
| `dnsmasq_sinkhole.conf` | `scripts/block_domain.sh --apply`가 참고하는 dnsmasq sinkhole 설정 템플릿. |

`#`으로 시작하는 줄은 주석으로 무시됩니다. 대소문자는 구분하지 않습니다(소문자로
정규화해서 비교).

자세한 내용은 루트 [README.md #14](../README.md#14-blacklist--whitelist-정책),
[#16](../README.md#16-dnsmasq-sinkhole)을 참고하세요.
