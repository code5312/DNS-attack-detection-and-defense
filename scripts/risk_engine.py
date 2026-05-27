#!/usr/bin/env python3
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
    CRITICAL = ("CRITICAL", "critical", "DNS 터널링 고위험, 즉시 대응 필요")

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
    max_entropy: float
    avg_qname_len: float
    max_qname_len: int
    query_count: int
    query_count_10s: int
    queries_per_minute: float
    txt_cname_ratio: float
    nxdomain_ratio: float
    base32_like_count: int
    hex_like_count: int
    snort_alerts: int
    blacklist_hit: int
    recommended_action: str


def load_config() -> dict:
    cfg_path = ROOT / "config" / "settings.yaml"
    if cfg_path.exists():
        with open(cfg_path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}


def load_line_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        t = line.strip().lower()
        if not t or t.startswith("#"):
            continue
        out.append(t)
    return out


def parse_snort_alerts(log_path: Path) -> dict[str, int]:
    if not log_path.exists():
        return {}
    ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    counts: dict[str, int] = {}
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        arrow = line.split("->")
        if len(arrow) >= 1:
            left = arrow[0]
            ips = ip_re.findall(left)
            if ips:
                src = ips[-1]
                counts[src] = counts.get(src, 0) + 1
    return counts


class RiskEngine:
    def __init__(self, config: dict | None = None):
        cfg = config or load_config()
        self.thresholds = cfg.get("thresholds", {})
        self.scores = cfg.get("risk_scores", {})
        levels = cfg.get("risk_levels", {})
        self.normal_max = levels.get("normal_max", 3)
        self.suspicious_max = levels.get("suspicious_max", 6)
        self.high_max = levels.get("high_max", 11)
        snort_cfg = cfg.get("snort", {})
        self.snort_log = ROOT / snort_cfg.get("alert_log", "results/snort_alerts.log")
        bl = cfg.get("blacklist", {})
        if isinstance(bl, dict):
            domains = bl.get("domains", ["attacker.lab", "evil.lab", "malicious.local"])
            domain_file = ROOT / bl.get("domain_file", "rules/domain_blacklist.txt")
        else:
            domains = bl or ["attacker.lab", "evil.lab", "malicious.local"]
            domain_file = ROOT / "rules/domain_blacklist.txt"
        merged = {d.lower() for d in domains if isinstance(d, str)}
        merged.update(load_line_list(domain_file))
        self.blacklist = merged
        whitelist_file = ROOT / (bl.get("whitelist_file", "rules/domain_whitelist.txt") if isinstance(bl, dict) else "rules/domain_whitelist.txt")
        self.whitelist = set(load_line_list(whitelist_file))

    def score_host(self, stats: HostStats, snort_count: int = 0, blacklist_hit: int = 0) -> RiskAssessment:
        t, s = self.thresholds, self.scores
        breakdown: dict[str, int] = {}

        query_count_10s = int(getattr(stats, "max_query_count_10s", 0))

        if stats.avg_qname_length > t.get("avg_qname_length", 50):
            breakdown["avg_qname_length"] = s.get("avg_qname_length", 2)
        if stats.max_qname_length > t.get("max_qname_length", 80):
            breakdown["max_qname_length"] = s.get("max_qname_length", 2)
        if stats.avg_entropy > t.get("avg_entropy", 3.5):
            breakdown["avg_entropy"] = s.get("avg_entropy", 2)
        if stats.max_entropy > t.get("max_entropy", 4.5):
            breakdown["max_entropy"] = s.get("max_entropy", 2)
        if stats.queries_per_minute > t.get("queries_per_minute", 100):
            breakdown["queries_per_minute"] = s.get("queries_per_minute", 3)
        if query_count_10s >= t.get("query_count_10s", 50):
            breakdown["query_count_10s"] = s.get("query_count_10s", 3)
        if stats.txt_cname_mx_ratio > t.get("txt_cname_ratio", 0.5):
            breakdown["txt_cname_mx_ratio"] = s.get("txt_cname_ratio", 2)
        if stats.nxdomain_ratio > t.get("nxdomain_ratio", 0.3):
            breakdown["nxdomain_ratio"] = s.get("nxdomain_ratio", 2)
        if stats.repeated_base_domain_max > t.get("repeated_base_domain", 30):
            breakdown["repeated_base_domain"] = s.get("repeated_base_domain", 2)
        if stats.base32_like_count > t.get("base32_like_count", 5):
            breakdown["base32_like_count"] = s.get("base32_like_count", 2)
        if stats.hex_like_count > t.get("hex_like_count", 5):
            breakdown["hex_like_count"] = s.get("hex_like_count", 2)
        snort_effective = min(snort_count, int(t.get("snort_alert_cap", 5)))
        if snort_effective > 0:
            breakdown["snort_alert"] = s.get("snort_alert", 3) * snort_effective
        if stats.attacker_domain_hits > 0:
            breakdown["attacker_domain"] = s.get("attacker_domain", 2)
        if blacklist_hit > 0:
            breakdown["blacklist_hit"] = max(s.get("blacklist_hit", 7), 7)

        total = sum(breakdown.values())
        verdict = self._verdict(total)
        action = {
            Verdict.NORMAL: "monitor",
            Verdict.SUSPICIOUS: "alert_and_log",
            Verdict.MALICIOUS: "block_recommended",
            Verdict.CRITICAL: "block_immediate",
        }[verdict]

        return RiskAssessment(
            src_ip=stats.src_ip,
            risk_score=total,
            verdict=verdict,
            breakdown=breakdown,
            avg_entropy=stats.avg_entropy,
            max_entropy=stats.max_entropy,
            avg_qname_len=stats.avg_qname_length,
            max_qname_len=stats.max_qname_length,
            query_count=stats.query_count,
            query_count_10s=query_count_10s,
            queries_per_minute=stats.queries_per_minute,
            txt_cname_ratio=stats.txt_cname_mx_ratio,
            nxdomain_ratio=stats.nxdomain_ratio,
            base32_like_count=stats.base32_like_count,
            hex_like_count=stats.hex_like_count,
            snort_alerts=snort_count,
            blacklist_hit=blacklist_hit,
            recommended_action=action,
        )

    def _verdict(self, score: int) -> Verdict:
        if score <= self.normal_max:
            return Verdict.NORMAL
        if score <= self.suspicious_max:
            return Verdict.SUSPICIOUS
        if score <= self.high_max:
            return Verdict.MALICIOUS
        return Verdict.CRITICAL

    def _blacklist_hits_by_src(self, analyzer: DNSAnalyzer) -> dict[str, int]:
        hits: dict[str, int] = {}
        for rec in analyzer.records:
            if rec.is_response:
                continue
            if rec.base_domain in self.whitelist:
                continue
            if rec.base_domain in self.blacklist:
                hits[rec.src_ip] = hits.get(rec.src_ip, 0) + 1
        return hits

    def analyze_pcap(self, pcap_path: Path, suspicious_domain: str = "attacker.lab") -> list[RiskAssessment]:
        analyzer = DNSAnalyzer(suspicious_domain=suspicious_domain)
        analyzer.analyze_pcap(pcap_path)
        host_stats = analyzer.compute_all_host_stats()
        snort_counts = parse_snort_alerts(self.snort_log)
        blacklist_hits = self._blacklist_hits_by_src(analyzer)
        return [
            self.score_host(s, snort_counts.get(ip, 0), blacklist_hits.get(ip, 0))
            for ip, s in host_stats.items()
        ]

    def save_results(self, assessments: list[RiskAssessment], pcap_name: str) -> tuple[Path, Path]:
        results_dir = ROOT / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        csv_path = results_dir / "detection_result.csv"
        json_path = results_dir / "detection_result.json"
        alert_path = results_dir / "alert.log"

        fields = [
            "timestamp", "pcap", "src_ip", "risk_score", "verdict_level", "verdict", "action",
            "avg_qname_len", "max_qname_len", "avg_entropy", "max_entropy",
            "queries_per_minute", "query_count", "query_count_10s", "txt_cname_ratio",
            "nxdomain_ratio", "base32_like_count", "hex_like_count", "snort_alerts",
            "blacklist_hit", "breakdown",
        ]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = []
        for a in assessments:
            rows.append({
                "timestamp": now,
                "pcap": pcap_name,
                "src_ip": a.src_ip,
                "risk_score": a.risk_score,
                "verdict_level": a.verdict.level,
                "verdict": a.verdict.code,
                "action": a.recommended_action,
                "avg_qname_len": a.avg_qname_len,
                "max_qname_len": a.max_qname_len,
                "avg_entropy": a.avg_entropy,
                "max_entropy": a.max_entropy,
                "queries_per_minute": a.queries_per_minute,
                "query_count": a.query_count,
                "query_count_10s": a.query_count_10s,
                "txt_cname_ratio": a.txt_cname_ratio,
                "nxdomain_ratio": a.nxdomain_ratio,
                "base32_like_count": a.base32_like_count,
                "hex_like_count": a.hex_like_count,
                "snort_alerts": a.snort_alerts,
                "blacklist_hit": a.blacklist_hit,
                "breakdown": json.dumps(a.breakdown, ensure_ascii=False),
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
                if a.verdict in {Verdict.MALICIOUS, Verdict.CRITICAL}:
                    f.write(
                        f"{now} [{a.verdict.level}] {a.src_ip} score={a.risk_score} "
                        f"verdict={a.verdict.code} action={a.recommended_action} breakdown={json.dumps(a.breakdown, ensure_ascii=False)}\n"
                    )
        return csv_path, alert_path

    def print_report(self, assessments: list[RiskAssessment]) -> None:
        print(f"\n{'='*60}")
        print("  Risk Engine - Detection Report")
        print(f"{'='*60}")
        for a in assessments:
            print(f"\n  src_ip          : {a.src_ip}")
            print(f"  avg/max entropy : {a.avg_entropy}/{a.max_entropy}")
            print(f"  avg/max qname   : {a.avg_qname_len}/{a.max_qname_len}")
            print(f"  qpm / q10s      : {a.queries_per_minute} / {a.query_count_10s}")
            print(f"  nxdomain_ratio  : {a.nxdomain_ratio}")
            print(f"  snort_alerts    : {a.snort_alerts}")
            print(f"  blacklist_hit   : {a.blacklist_hit}")
            print(f"  risk_score      : {a.risk_score}")
            print(f"  breakdown       : {a.breakdown}")
            print(f"  [{a.verdict.level}] {a.verdict.message}")
            print(f"  action          : {a.recommended_action}")


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
    parser.add_argument("--block", action="store_true", help="HIGH/CRITICAL verdict 시 iptables 차단")
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
        if a.verdict in {Verdict.MALICIOUS, Verdict.CRITICAL}:
            print(f"\n[!] {a.src_ip} → 차단 권고 (score={a.risk_score}, level={a.verdict.level})")
            if args.block:
                block_ip(a.src_ip, block_mode, dry_run=not args.live)


if __name__ == "__main__":
    main()
