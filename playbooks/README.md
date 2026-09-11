# playbooks/

"severity → 액션" 대응 정책을 코드가 아니라 YAML로 정의하는 디렉터리입니다.
로딩·매칭 로직은 [`../scripts/playbook.py`](../scripts/playbook.py) 하나에만 구현되어 있고,
`scripts/risk_engine.py`(offline)와 `engine/live_soar_engine.py`(live)가 이를 공유합니다.

## 파일

| 파일 | 용도 |
|---|---|
| `dns_tunneling_response.yaml` | 기본 playbook. `config/settings.yaml`의 `response.playbook_path`가 가리키는 파일 — 별도 지정이 없으면 offline/live 모두 이 파일을 씁니다. MALICIOUS 이상이면 `block_ip`+`notify`, SUSPICIOUS는 `log_only`만 실행하도록 되어 있으며, 이는 이 기능을 도입하기 전 하드코딩 로직과 동일하게 동작하도록 맞춘 값입니다. |
| `tiered_response_example.yaml` | 등급별로 다른 대응을 하는 예시. CRITICAL은 커스텀 TTL/모드로 즉시 차단, MALICIOUS는 차단 없이 알림만, SUSPICIOUS는 미지원 채널(`slack`)로 알림을 시도해 조용히 무시되는 경우까지 보여줍니다. `--playbook` 플래그로 테스트할 수 있습니다. |

## 규칙 작성 방법

```yaml
rules:
  - when: { min_severity: MALICIOUS }   # NORMAL < SUSPICIOUS < MALICIOUS < CRITICAL
    actions:
      - type: block_ip                  # mode/ttl_seconds 생략 시 config/settings.yaml의 response.* 사용
      - type: notify
        channel: log                    # 현재는 log만 지원
  - when: { min_severity: SUSPICIOUS }
    actions:
      - type: log_only
```

- 규칙은 파일에 적힌 순서대로 검사되고, 현재 이벤트의 severity가 규칙의
  `min_severity` **이상**이면 그 규칙만 적용되고 아래 규칙은 보지 않습니다.
  등급이 높은(엄격한) 규칙을 먼저 적어야 합니다.
- 지원 액션 타입: `block_ip`, `notify`, `log_only`. 새 타입을 추가하려면
  `scripts/risk_engine.py`(offline)와 `engine/live_soar_engine.py`의 `ActionWorker`(live)
  양쪽에 핸들러를 추가해야 합니다 — YAML에 없는 타입을 적어도 에러 없이 무시됩니다.
- 조건 평가는 severity 등급 비교만 지원합니다. `eval`/`exec` 등 임의 코드 실행 방식의
  조건식은 의도적으로 지원하지 않습니다.

## 다른 playbook 테스트

```bash
python scripts/risk_engine.py <pcap> --block --playbook playbooks/tiered_response_example.yaml
```

live 엔진에서 기본이 아닌 playbook을 쓰려면 `config/settings.yaml`의
`response.playbook_path`를 바꿔야 합니다(현재 실행 시점 오버라이드 플래그는 없습니다).

자세한 설명은 루트 [README.md #11](../README.md#11-playbook-대응-정책)을 참고하세요.
