#!/usr/bin/env python3
"""오프라인 Risk Engine과 Live SOAR Engine이 공유하는 Playbook 로더/매칭기.

playbooks/*.yaml 의 "조건(severity) → 액션 목록" 규칙을 읽고, 주어진
severity에 해당하는 액션 목록을 돌려준다. 액션을 실제로 실행하는 방법
(offline은 추천/dry-run, live는 즉시 실행 + TTL)은 각 엔진이 결정한다.

조건 평가는 severity 등급 비교만 지원한다 (eval/exec 등 임의 코드 실행
방식은 쓰지 않는다).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import yaml

SEVERITY_ORDER = ["NORMAL", "SUSPICIOUS", "MALICIOUS", "CRITICAL"]


def severity_from_score(score: int, risk_levels: dict) -> str:
    """risk_levels(normal_max/suspicious_max/high_max) 임계값으로 점수를 4단계 등급으로 변환.

    offline(RiskEngine._verdict)과 live(AnalysisWorker) 양쪽에서 같은 기준을
    쓰도록 하기 위한 공용 함수.
    """
    normal_max = risk_levels.get("normal_max", 3)
    suspicious_max = risk_levels.get("suspicious_max", 6)
    high_max = risk_levels.get("high_max", 11)
    if score <= normal_max:
        return "NORMAL"
    if score <= suspicious_max:
        return "SUSPICIOUS"
    if score <= high_max:
        return "MALICIOUS"
    return "CRITICAL"


@dataclass
class PlaybookRule:
    min_severity: str
    actions: list[dict]


def load_playbook(path: Path) -> list[PlaybookRule]:
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules: list[PlaybookRule] = []
    for raw in data.get("rules", []):
        if not isinstance(raw, dict):
            continue
        when = raw.get("when") or {}
        min_sev = str(when.get("min_severity", "")).upper()
        if min_sev not in SEVERITY_ORDER:
            continue
        actions = [a for a in (raw.get("actions") or []) if isinstance(a, dict) and a.get("type")]
        rules.append(PlaybookRule(min_severity=min_sev, actions=actions))
    return rules


def match_actions(severity: str, rules: list[PlaybookRule]) -> list[dict]:
    """severity에 대해 매칭되는 첫 규칙의 액션 목록만 반환.

    규칙은 파일에 적힌 순서대로 검사하며, 현재 severity가 규칙의
    min_severity 이상이면(더 엄격한 규칙에 해당하면) 그 규칙의 액션을
    실행하고 그 아래 규칙은 보지 않는다. 따라서 playbook 파일에는 등급이
    높은(엄격한) 규칙을 먼저 적어야 한다.
    """
    if severity not in SEVERITY_ORDER:
        return []
    sev_idx = SEVERITY_ORDER.index(severity)
    for rule in rules:
        if SEVERITY_ORDER.index(rule.min_severity) <= sev_idx:
            return rule.actions
    return []


def has_effective_action(actions: list[dict]) -> bool:
    """log_only(및 빈 목록)만 있는지 판단.

    log_only는 "이미 CSV/JSON/NDJSON에 기록되니 추가로 할 일 없음"을 뜻하므로,
    이것만 매칭된 이벤트는 ActionWorker의 쿨다운 타이머를 소모시키면 안 된다
    (그러면 바로 다음에 온 진짜 액션(block_ip/notify)이 쿨다운에 막혀 버린다).
    """
    return any(a.get("type") != "log_only" for a in actions)


def write_notification(log_path: Path, severity: str, src_ip: str, source: str, qname: str = "", channel: str = "log") -> None:
    """notify 액션 실행. offline(risk_engine.py)과 live(engine/live_soar_engine.py)가 공유.

    MVP는 "log" 채널만 지원하며, 다른 채널은 조용히 무시한다(향후 slack/webhook
    확장 지점). 실패해도 호출자를 막지 않도록 파일 I/O 에러는 삼킨다.
    """
    if channel != "log":
        return
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        qname_part = f" qname={qname}" if qname else ""
        with log_path.open("a", encoding="utf-8") as f:
            f.write(f"{now} [{severity}] src_ip={src_ip}{qname_part} channel=log source={source}\n")
    except Exception:
        pass
