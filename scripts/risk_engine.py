#!/usr/bin/env python3
"""
위험도 점수 산정 + 임계치 판단 (verdict)

Risk Score 예시:
  qname 평균 길이 > 50  → +2
  entropy > 3.5         → +2
  1분당 query > 100     → +3
  TXT/CNAME/MX > 50%    → +2
  base domain 반복 > 30 → +2
  Snort alert           → +3

Verdict:
  0~3  → [LOW]    normal
  4~6  → [MEDIUM] suspicious_dns_tunneling
  7+   → [HIGH]   malicious (차단 권고)

사용:
  python scripts/risk_engine.py pcaps/dnscat2_connect.pcap
  python scripts/risk_engine.py pcaps/dnscat2_connect.pcap --block
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from dns_analyzer import DNSAnalyzer, HostStats  # noqa: E402


class Verdict(Enum):
    NORMAL = ("LOW", "normal", "정상 DNS")
    SUSPICIOUS = ("MEDIUM", "suspicious_dns_tunneling", "의심 DNS 터널링 가능성")
    MALICIOUS = ("HIGH", "malicious", "DNS 터널링 의심, 차단 권고")

    def __init__(self, level: str, code: str, message: str):
        self.level = level
        self.code = code
        self.message = message


@dataclass
class RiskAssessment:
    src_ip: str
    risk_score: int
    verdict: Verdict
    breakdown: dict
    avg_entropy: float
    avg_qname_len: float
    query_count: int
    txt_cname_ratio: float
    snort_alerts: int
    recommended_action: str


def load_config() -> dict:
    cfg_path = ROOT / "config" / "settings.yaml"
    if cfg_path.exists():
        with open(cfg_path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}


def parse_snort_alerts(log_path: Path) -> dict[str, int]:
    if not log_path.exists():
        return {}
    ip_re = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    counts: dict[str, int] = {}
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        ips = ip_re.findall(line)
        if ips:
            counts[ips[0]] = counts.get(ips[0], 0) + 1
    return counts


class RiskEngine:
    def __init__(self, config: dict | None = None):
        cfg = config or load_config()
        self.thresholds = cfg.get("thresholds", {})
        self.scores = cfg.get("risk_scores", {})
        levels = cfg.get("risk_levels", {})
        self.normal_max = levels.get("normal_max", 3)
        self.suspicious_max = levels.get("suspicious_max", 6)
        snort_cfg = cfg.get("snort", {})
        self.snort_log = ROOT / snort_cfg.get("alert_log", "results/snort_alerts.log")

    def score_host(self, stats: HostStats, snort_count: int = 0) -> RiskAssessment:
        t, s = self.thresholds, self.scores
        breakdown: dict[str, int] = {}

        if stats.avg_qname_length > t.get("avg_qname_length", 50):
            breakdown["avg_qname_length"] = s.get("avg_qname_length", 2)
        if stats.max_qname_length > t.get("max_qname_length", 80):
            breakdown["max_qname_length"] = s.get("max_qname_length", 2)
        if stats.avg_entropy > t.get("avg_entropy", 3.5):
            breakdown["avg_entropy"] = s.get("avg_entropy", 2)
        if stats.queries_per_minute > t.get("queries_per_minute", 100):
            breakdown["queries_per_minute"] = s.get("queries_per_minute", 3)
        if stats.txt_cname_mx_ratio > t.get("txt_cname_ratio", 0.5):
            breakdown["txt_cname_mx_ratio"] = s.get("txt_cname_ratio", 2)
        if stats.repeated_base_domain_max > t.get("repeated_base_domain", 30):
            breakdown["repeated_base_domain"] = s.get("repeated_base_domain", 2)
        if snort_count > 0:
            breakdown["snort_alert"] = s.get("snort_alert", 3) * snort_count
        if stats.attacker_domain_hits > 0:
            breakdown["attacker_domain"] = s.get("attacker_domain", 2)
        if stats.unique_subdomain_ratio < t.get("unique_subdomain_ratio_low", 0.3):
            breakdown["low_unique_subdomain"] = s.get("high_entropy", 2)

        total = sum(breakdown.values())
        verdict = self._verdict(total)
        action = {
            Verdict.NORMAL: "monitor",
            Verdict.SUSPICIOUS: "alert_and_log",
            Verdict.MALICIOUS: "block_recommended",
        }[verdict]

        return RiskAssessment(
            src_ip=stats.src_ip,
            risk_score=total,
            verdict=verdict,
            breakdown=breakdown,
            avg_entropy=stats.avg_entropy,
            avg_qname_len=stats.avg_qname_length,
            query_count=stats.query_count,
            txt_cname_ratio=stats.txt_cname_mx_ratio,
            snort_alerts=snort_count,
            recommended_action=action,
        )

    def _verdict(self, score: int) -> Verdict:
        if score <= self.normal_max:
            return Verdict.NORMAL
        if score <= self.suspicious_max:
            return Verdict.SUSPICIOUS
        return Verdict.MALICIOUS

    def analyze_pcap(self, pcap_path: Path, suspicious_domain: str = "attacker.lab") -> list[RiskAssessment]:
        analyzer = DNSAnalyzer(suspicious_domain=suspicious_domain)
        analyzer.analyze_pcap(pcap_path)
        host_stats = analyzer.compute_all_host_stats()
        snort_counts = parse_snort_alerts(self.snort_log)
        return [self.score_host(s, snort_counts.get(ip, 0)) for ip, s in host_stats.items()]

    def save_results(
        self,
        assessments: list[RiskAssessment],
        pcap_name: str,
        analyzer: DNSAnalyzer | None = None,
    ) -> tuple[Path, Path]:
        results_dir = ROOT / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        csv_path = results_dir / "detection_result.csv"
        json_path = results_dir / "detection_result.json"
        alert_path = results_dir / "alert.log"

        fields = [
            "timestamp", "pcap", "src_ip", "avg_entropy", "avg_qname_len",
            "query_count", "txt_cname_ratio", "snort_alerts",
            "risk_score", "verdict_level", "verdict", "action", "breakdown",
        ]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = []
        for a in assessments:
            rows.append({
                "timestamp": now,
                "pcap": pcap_name,
                "src_ip": a.src_ip,
                "avg_entropy": a.avg_entropy,
                "avg_qname_len": a.avg_qname_len,
                "query_count": a.query_count,
                "txt_cname_ratio": a.txt_cname_ratio,
                "snort_alerts": a.snort_alerts,
                "risk_score": a.risk_score,
                "verdict_level": a.verdict.level,
                "verdict": a.verdict.code,
                "action": a.recommended_action,
                "breakdown": json.dumps(a.breakdown),
            })

        write_header = not csv_path.exists() or csv_path.stat().st_size == 0
        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            if write_header:
                w.writeheader()
            w.writerows(rows)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(
                [{**asdict(a), "verdict": a.verdict.code, "verdict_level": a.verdict.level} for a in assessments],
                f, indent=2, ensure_ascii=False,
            )

        with open(alert_path, "a", encoding="utf-8") as f:
            for a in assessments:
                if a.verdict != Verdict.NORMAL:
                    f.write(
                        f"{now} [{a.verdict.level}] {a.src_ip} score={a.risk_score} "
                        f"entropy={a.avg_entropy} qpm_related_queries={a.query_count} "
                        f"verdict={a.verdict.code} action={a.recommended_action}\n"
                    )
        return csv_path, alert_path

    def print_report(self, assessments: list[RiskAssessment]) -> None:
        print(f"\n{'='*60}")
        print("  Risk Engine - Detection Report")
        print(f"{'='*60}")
        for a in assessments:
            print(f"\n  src_ip         : {a.src_ip}")
            print(f"  avg_entropy    : {a.avg_entropy}")
            print(f"  avg_qname_len  : {a.avg_qname_len}")
            print(f"  query_count    : {a.query_count}")
            print(f"  txt_cname_ratio: {a.txt_cname_ratio}")
            print(f"  snort_alerts   : {a.snort_alerts}")
            print(f"  risk_score     : {a.risk_score}")
            print(f"  breakdown      : {a.breakdown}")
            print(f"  [{a.verdict.level}] {a.verdict.message}")
            print(f"  action         : {a.recommended_action}")


def block_ip(src_ip: str, mode: str = "kali_input", dry_run: bool = True) -> None:
    script = ROOT / "scripts" / "block_ip.sh"
    cmd = ["bash", str(script), src_ip, mode]
    if dry_run:
        print(f"[DRY-RUN] bash scripts/block_ip.sh {src_ip} {mode}")
    else:
        subprocess.run(cmd, check=True)


def main():
    parser = argparse.ArgumentParser(description="DNS 터널링 위험도 판단 엔진")
    parser.add_argument("pcap", help="pcap file path")
    parser.add_argument("--block", action="store_true", help="HIGH verdict 시 iptables 차단")
    parser.add_argument("--live", action="store_true", help="실제 차단 실행 (sudo 필요)")
    parser.add_argument("--snort-log", default=None, help="Snort alert log path")
    args = parser.parse_args()

    pcap = Path(args.pcap)
    if not pcap.exists():
        pcap = ROOT / "pcaps" / args.pcap

    engine = RiskEngine()
    if args.snort_log:
        engine.snort_log = Path(args.snort_log)

    assessments = engine.analyze_pcap(pcap)
    engine.print_report(assessments)
    csv_p, alert_p = engine.save_results(assessments, pcap.name)
    print(f"\n[+] detection_result.csv : {csv_p}")
    print(f"[+] alert.log            : {alert_p}")

    cfg = load_config()
    block_mode = cfg.get("response", {}).get("block_mode", "kali_input")

    for a in assessments:
        if a.verdict == Verdict.MALICIOUS:
            print(f"\n[!] {a.src_ip} → 차단 권고 (score={a.risk_score})")
            if args.block:
                block_ip(a.src_ip, block_mode, dry_run=not args.live)


if __name__ == "__main__":
    main()
