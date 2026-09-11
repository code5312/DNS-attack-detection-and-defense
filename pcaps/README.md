# pcaps/

분석 대상 pcap 파일을 두는 디렉터리입니다. `*.pcap`은 `.gitignore`로 제외되어
저장소에는 커밋되지 않고(`.gitkeep`만 추적), 로컬/VM에서 각자 생성해서 씁니다.

## 파일 생성 방법

```bash
python run.py sample   # normal_dns.pcap, dnscat2_connect.pcap 유사 샘플 생성 (실습용)
```

또는 실제 트래픽을 캡처하려면:

```bash
sudo bash scripts/capture_dns.sh <iface> <name>   # pcaps/<name>_<timestamp>.pcap 로 저장
```

## 사용처

- `run.py analyze / detect / compare / plot` 이 모두 이 디렉터리(또는 지정한 경로)의
  pcap을 입력으로 받습니다.
- `run.py sample`이 만드는 `dnscat2_connect.pcap`은 실제 dnscat2 트래픽이 아니라
  유사한 패턴(base32/hex-like 서브도메인, TXT/NULL qtype 등)을 흉내 낸 테스트용
  데이터입니다. 공격 자동화 코드는 포함하지 않습니다.

자세한 내용은 루트 [README.md #17](../README.md#17-pcap-수집)을 참고하세요.
