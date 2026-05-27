#!/usr/bin/env python3
"""
탐지 결과 시각화 (matplotlib)

그래프:
  - 정상 vs dnscat2 qname 길이 / entropy 비교
  - qtype 분포 막대그래프
  - 내부 IP별 risk score

사용:
  python scripts/plot_results.py pcaps/normal_dns.pcap pcaps/dnscat2_connect.pcap
  python scripts/plot_results.py --csv results/detection_result.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from dns_analyzer import DNSAnalyzer  # noqa: E402


def plot_compare(pcaps: list[tuple[str, Path]], out_dir: Path) -> None:
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] pip install matplotlib")
        sys.exit(1)

    out_dir.mkdir(parents=True, exist_ok=True)
    labels, avg_lens, avg_ents, qpm_list = [], [], [], []

    for label, path in pcaps:
        az = DNSAnalyzer()
        az.analyze_pcap(path)
        stats = az.compute_all_host_stats()
        for s in stats.values():
            labels.append(f"{label}\n{s.src_ip}")
            avg_lens.append(s.avg_qname_length)
            avg_ents.append(s.avg_entropy)
            qpm_list.append(s.queries_per_minute)

    fig, axes = plt.subplots(1, 3, figsize=(14, 5))

    x = range(len(labels))
    axes[0].bar(x, avg_lens, color=["#4caf50", "#f44336"] * (len(x) // 2 + 1))
    axes[0].set_title("Average qname Length")
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(labels, rotation=15, ha="right")

    axes[1].bar(x, avg_ents, color=["#2196f3", "#ff9800"] * (len(x) // 2 + 1))
    axes[1].set_title("Average Shannon Entropy")
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(labels, rotation=15, ha="right")

    axes[2].bar(x, qpm_list, color=["#9c27b0", "#e91e63"] * (len(x) // 2 + 1))
    axes[2].set_title("Queries per Minute")
    axes[2].set_xticks(x)
    axes[2].set_xticklabels(labels, rotation=15, ha="right")

    plt.tight_layout()
    path = out_dir / "compare_metrics.png"
    plt.savefig(path, dpi=150)
    print(f"[+] Saved: {path}")
    plt.close()

    # qtype 분포 (마지막 pcap)
    label, pcap_path = pcaps[-1]
    az = DNSAnalyzer()
    az.analyze_pcap(pcap_path)
    stats = az.compute_all_host_stats()
    if stats:
        s = next(iter(stats.values()))
        qtypes = list(s.qtype_distribution.keys())
        counts = list(s.qtype_distribution.values())
        fig2, ax2 = plt.subplots(figsize=(8, 5))
        ax2.bar(qtypes, counts, color="#607d8b")
        ax2.set_title(f"Qtype Distribution ({label})")
        plt.tight_layout()
        p2 = out_dir / f"qtype_dist_{pcap_path.stem}.png"
        plt.savefig(p2, dpi=150)
        print(f"[+] Saved: {p2}")
        plt.close()


def plot_risk_csv(csv_path: Path, out_dir: Path) -> None:
    import csv
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] pip install matplotlib")
        sys.exit(1)

    ips, scores, levels = [], [], []
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"src_ip", "risk_score", "verdict_level"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError(f"CSV missing required fields: {required}")
        for row in reader:
            ips.append(row["src_ip"])
            scores.append(int(row["risk_score"]))
            levels.append(row["verdict_level"])

    colors = {"LOW": "#4caf50", "MEDIUM": "#ff9800", "HIGH": "#f44336"}
    bar_colors = [colors.get(l, "#9e9e9e") for l in levels]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(ips, scores, color=bar_colors)
    ax.set_title("Risk Score by Internal IP")
    ax.set_ylabel("risk_score")
    ax.axhline(y=3, color="green", linestyle="--", alpha=0.5, label="normal max")
    ax.axhline(y=6, color="orange", linestyle="--", alpha=0.5, label="suspicious max")
    ax.legend()
    plt.tight_layout()
    out = out_dir / "risk_scores.png"
    plt.savefig(out, dpi=150)
    print(f"[+] Saved: {out}")
    plt.close()


def main():
    parser = argparse.ArgumentParser(description="탐지 결과 시각화")
    parser.add_argument("pcap", nargs="*", help="pcap files to compare")
    parser.add_argument("--csv", help="detection_result.csv for risk chart")
    args = parser.parse_args()

    out_dir = ROOT / "results" / "graphs"

    if args.csv:
        plot_risk_csv(Path(args.csv), out_dir)
        return

    if len(args.pcap) < 1:
        parser.error("pcap file(s) or --csv required")

    pcaps = []
    for i, p in enumerate(args.pcap):
        path = Path(p)
        if not path.exists():
            path = ROOT / "pcaps" / p
        label = "normal" if "normal" in path.name else f"attack_{i}"
        pcaps.append((label, path))

    plot_compare(pcaps, out_dir)


if __name__ == "__main__":
    main()
