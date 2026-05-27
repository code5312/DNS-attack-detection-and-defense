#!/usr/bin/env python3
"""
Scapy 기반 DNS 패킷 오프라인 분석기.

역할:
  - pcap에서 DNS Query/Response 추출 (IPv4 + UDP DNS)
  - qname 정규화, subdomain/base_domain 분리
  - Shannon entropy 및 문자 기반 feature 산출
  - RCODE 기반 NXDOMAIN 분석
  - src_ip 기준 host_stats + 비교 리포트 생성
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import string
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from scapy.all import DNS, IP, UDP  # type: ignore
from scapy.utils import PcapReader  # type: ignore

ROOT = Path(__file__).resolve().parent.parent

QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT",
    28: "AAAA", 10: "NULL", 255: "ANY",
}
SUSPICIOUS_QTYPES = {"TXT", "CNAME", "MX", "NULL", "TYPE65", "ANY"}
BASE32_CHARS = set("abcdefghijklmnopqrstuvwxyz234567")
HEX_CHARS = set(string.hexdigits.lower())


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def qtype_name(qtype: int) -> str:
    return QTYPE_MAP.get(qtype, f"TYPE{qtype}")


def normalize_qname(raw) -> str:
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = str(raw)
    text = text.strip().lower().rstrip(".")
    return "".join(ch for ch in text if ch.isalnum() or ch in "-._")


def split_domain(qname: str) -> tuple[str, str]:
    parts = [p for p in qname.split(".") if p]
    if len(parts) < 2:
        return "", qname
    base = ".".join(parts[-2:])
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    return subdomain, base


def safe_ratio(num: int, den: int) -> float:
    return round((num / den), 4) if den else 0.0


def qname_features(qname: str, subdomain: str) -> dict[str, float | int | bool]:
    target = subdomain if subdomain else qname
    label_count = len([p for p in qname.split(".") if p])
    alnum = [c for c in target if c.isalnum()]
    n = len(alnum)
    digits = sum(c.isdigit() for c in alnum)
    alphas = sum(c.isalpha() for c in alnum)
    uniq = len(set(alnum))
    lowered = "".join(alnum).lower()

    base32_like = n >= 12 and all(c in BASE32_CHARS for c in lowered)
    hex_like = n >= 12 and all(c in HEX_CHARS for c in lowered)

    return {
        "label_count": label_count,
        "digit_ratio": safe_ratio(digits, n),
        "alpha_ratio": safe_ratio(alphas, n),
        "unique_char_ratio": safe_ratio(uniq, n),
        "base32_like": base32_like,
        "hex_like": hex_like,
    }


@dataclass
class DNSPacketRecord:
    timestamp: float
    timestamp_str: str
    src_ip: str
    dst_ip: str
    is_response: bool
    txid: int
    qname: str
    qtype: str
    qname_length: int
    subdomain: str
    subdomain_length: int
    base_domain: str
    entropy: float
    rcode: int
    is_nxdomain: bool
    is_suspicious_qtype: bool
    label_count: int
    digit_ratio: float
    alpha_ratio: float
    unique_char_ratio: float
    base32_like: bool
    hex_like: bool


@dataclass
class HostStats:
    src_ip: str
    query_count: int = 0
    response_count: int = 0
    nxdomain_count: int = 0
    nxdomain_ratio: float = 0.0
    unique_qname_count: int = 0
    queries_per_second: float = 0.0
    queries_per_minute: float = 0.0
    avg_qname_length: float = 0.0
    max_qname_length: int = 0
    avg_subdomain_length: float = 0.0
    avg_entropy: float = 0.0
    max_entropy: float = 0.0
    txt_cname_mx_ratio: float = 0.0
    suspicious_qtype_ratio: float = 0.0
    unique_subdomain_ratio: float = 0.0
    repeated_base_domain_max: int = 0
    attacker_domain_hits: int = 0
    avg_label_count: float = 0.0
    avg_digit_ratio: float = 0.0
    avg_alpha_ratio: float = 0.0
    avg_unique_char_ratio: float = 0.0
    base32_like_count: int = 0
    hex_like_count: int = 0
    qtype_distribution: dict = field(default_factory=dict)
    window_seconds: float = 0.0
    max_query_count_10s: int = 0


class DNSAnalyzer:
    def __init__(self, suspicious_domain: str = "attacker.lab", time_window: float = 10.0):
        self.suspicious_domain = suspicious_domain.lower()
        self.time_window = time_window
        self.records: list[DNSPacketRecord] = []

    def _extract_qd(self, dns: DNS):
        try:
            qd = dns.qd
            if qd is None:
                return None
            if hasattr(qd, "qname"):
                return qd
            if isinstance(qd, list) and qd and hasattr(qd[0], "qname"):
                return qd[0]
            return None
        except Exception:
            return None

    def parse_packet(self, pkt) -> DNSPacketRecord | None:
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
            return None

        dns = pkt[DNS]
        qd = self._extract_qd(dns)
        if not qd:
            return None

        qname = normalize_qname(qd.qname)
        if not qname:
            return None

        subdomain, base = split_domain(qname)
        ent = shannon_entropy(subdomain if subdomain else qname)
        qtype = qtype_name(int(qd.qtype))
        feats = qname_features(qname, subdomain)
        ts = float(pkt.time)
        rec = DNSPacketRecord(
            timestamp=ts,
            timestamp_str=datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            is_response=bool(dns.qr == 1),
            txid=int(dns.id),
            qname=qname,
            qtype=qtype,
            qname_length=len(qname),
            subdomain=subdomain,
            subdomain_length=len(subdomain),
            base_domain=base,
            entropy=round(ent, 4),
            rcode=int(dns.rcode),
            is_nxdomain=int(dns.rcode) == 3,
            is_suspicious_qtype=qtype in SUSPICIOUS_QTYPES,
            label_count=int(feats["label_count"]),
            digit_ratio=float(feats["digit_ratio"]),
            alpha_ratio=float(feats["alpha_ratio"]),
            unique_char_ratio=float(feats["unique_char_ratio"]),
            base32_like=bool(feats["base32_like"]),
            hex_like=bool(feats["hex_like"]),
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
        queries = [r for r in recs if not r.is_response]
        responses = [r for r in recs if r.is_response]
        n = len(queries)
        if n == 0:
            return HostStats(src_ip=src_ip, response_count=len(responses))

        lengths = [r.qname_length for r in queries]
        sub_lens = [r.subdomain_length for r in queries]
        entropies = [r.entropy for r in queries]
        subdomains = [r.subdomain for r in queries if r.subdomain]
        bases = [r.base_domain for r in queries]

        t_min, t_max = min(r.timestamp for r in queries), max(r.timestamp for r in queries)
        duration = max(t_max - t_min, 0.001)

        qtype_dist: dict[str, int] = {}
        for r in queries:
            qtype_dist[r.qtype] = qtype_dist.get(r.qtype, 0) + 1

        txt_cname_mx = sum(1 for r in queries if r.qtype in {"TXT", "CNAME", "MX"})
        susp = sum(1 for r in queries if r.is_suspicious_qtype)
        base_cnt: dict[str, int] = {}
        for b in bases:
            base_cnt[b] = base_cnt.get(b, 0) + 1

        unique_qnames = len(set(r.qname for r in queries))
        unique_subs = len(set(subdomains)) / len(subdomains) if subdomains else 1.0

        nxdomain_count = sum(1 for r in responses if r.is_nxdomain)

        # real sliding-window max query count over 10s
        q_ts = sorted(r.timestamp for r in queries)
        left = 0
        max_q10 = 0
        for right, ts in enumerate(q_ts):
            while ts - q_ts[left] > 10.0:
                left += 1
            curr = right - left + 1
            if curr > max_q10:
                max_q10 = curr

        return HostStats(
            src_ip=src_ip,
            query_count=n,
            response_count=len(responses),
            nxdomain_count=nxdomain_count,
            nxdomain_ratio=round(nxdomain_count / max(len(responses), 1), 2),
            unique_qname_count=unique_qnames,
            queries_per_second=round(n / duration, 2),
            queries_per_minute=round(n / (duration / 60), 2),
            avg_qname_length=round(sum(lengths) / n, 2),
            max_qname_length=max(lengths),
            avg_subdomain_length=round(sum(sub_lens) / n, 2),
            avg_entropy=round(sum(entropies) / n, 2),
            max_entropy=round(max(entropies), 2),
            txt_cname_mx_ratio=round(txt_cname_mx / n, 2),
            suspicious_qtype_ratio=round(susp / n, 2),
            unique_subdomain_ratio=round(unique_subs, 2),
            repeated_base_domain_max=max(base_cnt.values()) if base_cnt else 0,
            attacker_domain_hits=sum(
                1
                for r in queries
                if r.qname == self.suspicious_domain or r.qname.endswith("." + self.suspicious_domain)
            ),
            avg_label_count=round(sum(r.label_count for r in queries) / n, 2),
            avg_digit_ratio=round(sum(r.digit_ratio for r in queries) / n, 2),
            avg_alpha_ratio=round(sum(r.alpha_ratio for r in queries) / n, 2),
            avg_unique_char_ratio=round(sum(r.unique_char_ratio for r in queries) / n, 2),
            base32_like_count=sum(1 for r in queries if r.base32_like),
            hex_like_count=sum(1 for r in queries if r.hex_like),
            qtype_distribution=qtype_dist,
            window_seconds=round(duration, 2),
            max_query_count_10s=max_q10,
        )

    def compute_all_host_stats(self) -> dict[str, HostStats]:
        return {ip: self.compute_host_stats(ip, recs) for ip, recs in self.group_by_src().items()}

    def save_packets_csv(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "timestamp", "src_ip", "dst_ip", "is_response", "rcode", "is_nxdomain", "txid",
            "qname", "qtype", "qname_length", "subdomain", "subdomain_length", "base_domain",
            "entropy", "is_suspicious_qtype", "label_count", "digit_ratio", "alpha_ratio",
            "unique_char_ratio", "base32_like", "hex_like",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in self.records:
                w.writerow({k: getattr(r, k) for k in fields})

    def save_host_stats_csv(self, path: Path, stats: dict[str, HostStats]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = list(HostStats.__dataclass_fields__.keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for s in stats.values():
                row = asdict(s)
                row["qtype_distribution"] = json.dumps(s.qtype_distribution, ensure_ascii=False)
                w.writerow(row)

    def print_summary(self, label: str, stats: dict[str, HostStats]) -> None:
        print(f"\n{'=' * 60}")
        print(f"  {label}")
        print(f"{'=' * 60}")
        print(f"  Total DNS packets (query+response): {len(self.records)}")
        for ip, s in stats.items():
            print(f"\n  [Host] {ip}")
            print(f"    query_count            = {s.query_count}")
            print(f"    response_count         = {s.response_count}")
            print(f"    nxdomain_count/ratio   = {s.nxdomain_count} / {s.nxdomain_ratio}")
            print(f"    qpm                    = {s.queries_per_minute}")
            print(f"    avg_qname_len          = {s.avg_qname_length}  max = {s.max_qname_length}")
            print(f"    avg_entropy            = {s.avg_entropy}  max = {s.max_entropy}")
            print(f"    suspicious_qtype_ratio = {s.suspicious_qtype_ratio}")
            print(f"    base32_like/hex_like   = {s.base32_like_count}/{s.hex_like_count}")


def compare_pcaps(paths: list[Path], out_dir: Path) -> None:
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
                "response_count": s.response_count,
                "nxdomain_ratio": s.nxdomain_ratio,
                "avg_qname_length": s.avg_qname_length,
                "avg_entropy": s.avg_entropy,
                "qpm": s.queries_per_minute,
                "digit_ratio": s.avg_digit_ratio,
                "unique_char_ratio": s.avg_unique_char_ratio,
                "suspicious_qtype_ratio": s.suspicious_qtype_ratio,
                "base32_like_count": s.base32_like_count,
                "hex_like_count": s.hex_like_count,
                "qtype_distribution": json.dumps(s.qtype_distribution),
            })
    out = out_dir / "compare_summary.csv"
    out_dir.mkdir(parents=True, exist_ok=True)
    if results:
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
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
