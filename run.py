#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"
ENGINE = ROOT / "engine"


def run_script(path: Path, args: list[str]) -> int:
    cmd = [sys.executable, str(path)] + args
    return subprocess.call(cmd)


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS Tunneling Detection/Response CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_an = sub.add_parser("analyze", help="Scapy DNS 분석 → CSV/JSON")
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

    sub.add_parser("sample", help="테스트용 샘플 pcap 생성")
    sub.add_parser("live", help="실시간 SOAR 엔진 실행")

    args = parser.parse_args()

    if args.cmd == "analyze":
        extra = ["--compare"] if args.compare else []
        raise SystemExit(run_script(SCRIPTS / "dns_analyzer.py", list(args.pcap) + extra))

    if args.cmd == "detect":
        extra = [args.pcap]
        if args.block:
            extra.append("--block")
        if args.live:
            extra.append("--live")
        raise SystemExit(run_script(SCRIPTS / "risk_engine.py", extra))

    if args.cmd == "compare":
        raise SystemExit(run_script(SCRIPTS / "dns_analyzer.py", list(args.pcap) + ["--compare"]))

    if args.cmd == "plot":
        raise SystemExit(run_script(SCRIPTS / "plot_results.py", list(args.pcap)))

    if args.cmd == "sample":
        raise SystemExit(run_script(SCRIPTS / "generate_sample_pcap.py", []))

    if args.cmd == "live":
        raise SystemExit(run_script(ENGINE / "live_soar_engine.py", []))


if __name__ == "__main__":
    main()
