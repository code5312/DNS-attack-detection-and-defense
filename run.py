#!/usr/bin/env python3
"""
DNS 터널링 탐지·대응 — 통합 실행 진입점

실습 흐름:
  1. pcaps/ 에 pcap 수집
  2. python run.py analyze pcaps/normal_dns.pcap
  3. python run.py detect pcaps/dnscat2_connect.pcap
  4. python run.py compare pcaps/normal_dns.pcap pcaps/dnscat2_connect.pcap
  5. python run.py plot pcaps/normal_dns.pcap pcaps/dnscat2_connect.pcap
  6. python run.py detect pcaps/dnscat2_connect.pcap --block --live  (Ubuntu/Kali)
"""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"


def run_script(name: str, args: list[str]) -> int:
    cmd = [sys.executable, str(SCRIPTS / name)] + args
    return subprocess.call(cmd)


def main():
    parser = argparse.ArgumentParser(description="DNS Tunneling Detection")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_an = sub.add_parser("analyze", help="Scapy DNS 분석 → CSV")
    p_an.add_argument("pcap", nargs="+")
    p_an.add_argument("--compare", action="store_true")

    p_det = sub.add_parser("detect", help="위험도 점수 + verdict + 로그")
    p_det.add_argument("pcap")
    p_det.add_argument("--block", action="store_true")
    p_det.add_argument("--live", action="store_true")

    p_cmp = sub.add_parser("compare", help="정상 vs 공격 비교")
    p_cmp.add_argument("pcap", nargs=2)

    p_plot = sub.add_parser("plot", help="결과 그래프 생성")
    p_plot.add_argument("pcap", nargs="+")

    p_gen = sub.add_parser("sample", help="테스트용 샘플 pcap 생성")

    p_live = sub.add_parser("live-soar", help="실시간 Live SOAR DNS 탐지/대응 엔진 실행")

    args = parser.parse_args()

    if args.cmd == "analyze":
        a = ["--compare"] if args.compare else []
        sys.exit(run_script("dns_analyzer.py", list(args.pcap) + a))

    if args.cmd == "detect":
        a = [args.pcap]
        if args.block:
            a.append("--block")
        if args.live:
            a.append("--live")
        sys.exit(run_script("risk_engine.py", a))

    if args.cmd == "compare":
        sys.exit(run_script("dns_analyzer.py", list(args.pcap) + ["--compare"]))

    if args.cmd == "plot":
        sys.exit(run_script("plot_results.py", list(args.pcap)))

    if args.cmd == "sample":
        sys.exit(run_script("generate_sample_pcap.py", []))

    if args.cmd == "live-soar":
        cmd = [sys.executable, str(ROOT / "live_soar_engine.py")]
        sys.exit(subprocess.call(cmd))


if __name__ == "__main__":
    main()
