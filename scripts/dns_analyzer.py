#!/usr/bin/env python3
"""
Scapy 기반 DNS 패킷 분석 (프로젝트 핵심)

역할:
  - pcap에서 DNS Query 추출 (qname, qtype, src_ip, timestamp)
  - qname/subdomain 길이, Shannon entropy, 빈도, qtype 분포
  - 내부 IP별 통계 생성 → CSV/JSON 저장

사용:
  python scripts/dns_analyzer.py pcaps/normal_dns.pcap
  python scripts/dns_analyzer.py pcaps/dnscat2_connect.pcap -o results/attack_packets.csv
  python scripts/dns_analyzer.py pcaps/normal_dns.pcap pcaps/dnscat2_connect.pcap --compare
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from scapy.all import DNS, IP, UDP  # type: ignore
from scapy.utils import PcapReader  # type: ignore

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# 1) Shannon entropy (보고서 수식 ↔ 코드 연결)
# H(X) = -Σ p(x) log2 p(x)
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """문자열의 Shannon entropy 계산."""
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


# ---------------------------------------------------------------------------
# DNS 유틸
# ---------------------------------------------------------------------------

QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT",
    28: "AAAA", 10: "NULL", 255: "ANY",
}

SUSPICIOUS_QTYPES = {"TXT", "CNAME", "MX", "NULL"}


def qtype_name(qtype: int) -> str:
    return QTYPE_MAP.get(qtype, f"TYPE{qtype}")


def decode_qname(raw) -> str:
    if isinstance(raw, str):
        return raw.rstrip(".")
    labels, i, data = [], 0, bytes(raw)
    while i < len(data):
        ln = data[i]
        if ln == 0:
            break
        i += 1
        labels.append(data[i : i + ln].decode("utf-8", errors="replace"))
        i += ln
    return ".".join(labels)


def split_domain(qname: str) -> tuple[str, str]:
    parts = qname.rstrip(".").split(".")
    if len(parts) < 2:
        return qname, qname
    base = ".".join(parts[-2:])
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    return subdomain, base


# ---------------------------------------------------------------------------
# 데이터 모델
# ---------------------------------------------------------------------------

@dataclass
class DNSPacketRecord:
    timestamp: float
    timestamp_str: str
    src_ip: str
    dst_ip: str
    qname: str
    qtype: str
    qname_length: int
    subdomain: str
    subdomain_length: int
    base_domain: str
    entropy: float


@dataclass
class HostStats:
    src_ip: str
    query_count: int = 0
    unique_qname_count: int = 0
    queries_per_second: float = 0.0
    queries_per_minute: float = 0.0
    avg_qname_length: float = 0.0
    max_qname_length: int = 0
    avg_subdomain_length: float = 0.0
    avg_entropy: float = 0.0
    max_entropy: float = 0.0
    txt_cname_mx_ratio: float = 0.0
    unique_subdomain_ratio: float = 0.0
    repeated_base_domain_max: int = 0
    attacker_domain_hits: int = 0
    qtype_distribution: dict = field(default_factory=dict)
    window_seconds: float = 0.0


# ---------------------------------------------------------------------------
# 분석기
# ---------------------------------------------------------------------------

class DNSAnalyzer:
    def __init__(self, suspicious_domain: str = "attacker.lab", time_window: float = 10.0):
        self.suspicious_domain = suspicious_domain
        self.time_window = time_window
        self.records: list[DNSPacketRecord] = []

    def parse_packet(self, pkt) -> DNSPacketRecord | None:
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
            return None
        dns = pkt[DNS]
        if dns.qr != 0 or not dns.qd:
            return None

        qd = dns.qd
        qname = decode_qname(qd.qname)
        subdomain, base = split_domain(qname)
        ent = shannon_entropy(subdomain) if subdomain else shannon_entropy(qname)
        ts = float(pkt.time)

        rec = DNSPacketRecord(
            timestamp=ts,
            timestamp_str=datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            qname=qname,
            qtype=qtype_name(int(qd.qtype)),
            qname_length=len(qname),
            subdomain=subdomain,
            subdomain_length=len(subdomain),
            base_domain=base,
            entropy=round(ent, 4),
        )
        self.records.append(rec)
        return rec

    def analyze_pcap(self, pcap_path: str | Path) -> list[DNSPacketRecord]:
        self.records = []
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(path)
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                self.parse_packet(pkt)
        return self.records

    def group_by_src(self) -> dict[str, list[DNSPacketRecord]]:
        grouped: dict[str, list[DNSPacketRecord]] = defaultdict(list)
        for r in self.records:
            grouped[r.src_ip].append(r)
        return dict(grouped)

    def compute_host_stats(self, src_ip: str, recs: list[DNSPacketRecord]) -> HostStats:
        n = len(recs)
        if n == 0:
            return HostStats(src_ip=src_ip)

        lengths = [r.qname_length for r in recs]
        sub_lens = [r.subdomain_length for r in recs]
        entropies = [r.entropy for r in recs]
        subdomains = [r.subdomain for r in recs if r.subdomain]
        bases = [r.base_domain for r in recs]

        t_min, t_max = min(r.timestamp for r in recs), max(r.timestamp for r in recs)
        duration = max(t_max - t_min, 0.001)

        qtype_dist: dict[str, int] = {}
        for r in recs:
            qtype_dist[r.qtype] = qtype_dist.get(r.qtype, 0) + 1

        susp = sum(1 for r in recs if r.qtype in SUSPICIOUS_QTYPES)
        base_cnt: dict[str, int] = {}
        for b in bases:
            base_cnt[b] = base_cnt.get(b, 0) + 1

        unique_qnames = len(set(r.qname for r in recs))
        unique_subs = len(set(subdomains)) / len(subdomains) if subdomains else 1.0

        return HostStats(
            src_ip=src_ip,
            query_count=n,
            unique_qname_count=unique_qnames,
            queries_per_second=round(n / duration, 2),
            queries_per_minute=round(n / (duration / 60), 2),
            avg_qname_length=round(sum(lengths) / n, 2),
            max_qname_length=max(lengths),
            avg_subdomain_length=round(sum(sub_lens) / n, 2),
            avg_entropy=round(sum(entropies) / n, 2),
            max_entropy=round(max(entropies), 2),
            txt_cname_mx_ratio=round(susp / n, 2),
            unique_subdomain_ratio=round(unique_subs, 2),
            repeated_base_domain_max=max(base_cnt.values()) if base_cnt else 0,
            attacker_domain_hits=sum(1 for r in recs if self.suspicious_domain in r.qname),
            qtype_distribution=qtype_dist,
            window_seconds=round(duration, 2),
        )

    def compute_all_host_stats(self) -> dict[str, HostStats]:
        return {
            ip: self.compute_host_stats(ip, recs)
            for ip, recs in self.group_by_src().items()
        }

    # --- 저장 ---

    def save_packets_csv(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "timestamp", "src_ip", "dst_ip", "qname", "qtype",
            "qname_length", "subdomain_length", "base_domain", "entropy",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in self.records:
                w.writerow({
                    "timestamp": r.timestamp_str,
                    "src_ip": r.src_ip,
                    "dst_ip": r.dst_ip,
                    "qname": r.qname,
                    "qtype": r.qtype,
                    "qname_length": r.qname_length,
                    "subdomain_length": r.subdomain_length,
                    "base_domain": r.base_domain,
                    "entropy": r.entropy,
                })

    def save_host_stats_csv(self, path: Path, stats: dict[str, HostStats]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "src_ip", "query_count", "unique_qname_count",
            "queries_per_second", "queries_per_minute",
            "avg_qname_length", "max_qname_length", "avg_subdomain_length",
            "avg_entropy", "max_entropy", "txt_cname_mx_ratio",
            "unique_subdomain_ratio", "repeated_base_domain_max",
            "attacker_domain_hits", "qtype_distribution", "window_seconds",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for s in stats.values():
                row = asdict(s)
                row["qtype_distribution"] = json.dumps(s.qtype_distribution, ensure_ascii=False)
                w.writerow(row)

    def print_summary(self, label: str, stats: dict[str, HostStats]) -> None:
        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")
        print(f"  Total DNS queries: {len(self.records)}")
        for ip, s in stats.items():
            print(f"\n  [Host] {ip}")
            print(f"    query_count      = {s.query_count}")
            print(f"    qpm              = {s.queries_per_minute}")
            print(f"    avg_qname_len    = {s.avg_qname_length}  max = {s.max_qname_length}")
            print(f"    avg_entropy      = {s.avg_entropy}  max = {s.max_entropy}")
            print(f"    txt/cname/mx %   = {s.txt_cname_mx_ratio * 100:.0f}%")
            print(f"    qtype_dist       = {s.qtype_distribution}")
            print(f"    attacker.lab     = {s.attacker_domain_hits} hits")


def compare_pcaps(paths: list[Path], out_dir: Path) -> None:
    """정상 vs 공격 pcap 비교."""
    results = []
    for p in paths:
        az = DNSAnalyzer()
        az.analyze_pcap(p)
        stats = az.compute_all_host_stats()
        for ip, s in stats.items():
            results.append({
                "pcap": p.name,
                "src_ip": ip,
                "query_count": s.query_count,
                "avg_qname_length": s.avg_qname_length,
                "avg_entropy": s.avg_entropy,
                "qpm": s.queries_per_minute,
                "txt_cname_mx_ratio": s.txt_cname_mx_ratio,
                "qtype_distribution": json.dumps(s.qtype_distribution),
            })
    out = out_dir / "compare_summary.csv"
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()) if results else [])
        if results:
            w.writeheader()
            w.writerows(results)
    print(f"\n[+] Comparison saved: {out}")


def main():
    parser = argparse.ArgumentParser(description="Scapy DNS 패킷 분석기")
    parser.add_argument("pcap", nargs="+", help="pcap file(s)")
    parser.add_argument("-o", "--output", help="per-packet CSV output path")
    parser.add_argument("--host-csv", default=None, help="per-host stats CSV")
    parser.add_argument("--compare", action="store_true", help="compare multiple pcaps")
    parser.add_argument("--json", dest="json_out", help="JSON summary output")
    args = parser.parse_args()

    paths = [Path(p) if Path(p).exists() else ROOT / p for p in args.pcap]

    if args.compare and len(paths) > 1:
        compare_pcaps(paths, ROOT / "results")
        return

    pcap = paths[0]
    analyzer = DNSAnalyzer()
    analyzer.analyze_pcap(pcap)
    stats = analyzer.compute_all_host_stats()
    analyzer.print_summary(pcap.name, stats)

    stem = pcap.stem
    results_dir = ROOT / "results"
    pkt_csv = Path(args.output) if args.output else results_dir / f"{stem}_packets.csv"
    host_csv = Path(args.host_csv) if args.host_csv else results_dir / f"{stem}_host_stats.csv"

    analyzer.save_packets_csv(pkt_csv)
    analyzer.save_host_stats_csv(host_csv, stats)
    print(f"\n[+] Packets CSV : {pkt_csv}")
    print(f"[+] Host stats  : {host_csv}")

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump({ip: asdict(s) for ip, s in stats.items()}, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON        : {out}")


if __name__ == "__main__":
    main()
