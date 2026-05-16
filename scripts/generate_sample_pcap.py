#!/usr/bin/env python3
"""테스트용 dnscat2 유사 + 정상 DNS pcap 생성."""

import sys
from pathlib import Path

from scapy.all import IP, UDP, DNS, DNSQR, wrpcap  # type: ignore

ROOT = Path(__file__).resolve().parent.parent
PCAPS = ROOT / "pcaps"
PCAPS.mkdir(parents=True, exist_ok=True)


def make_query(src, dst, qname, qtype, ts):
    pkt = IP(src=src, dst=dst) / UDP(sport=54321, dport=53)
    pkt = pkt / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    pkt.time = ts
    return pkt


def build_normal():
    src, dst = "172.30.1.44", "8.8.8.8"
    pkts = [make_query(src, dst, f"www.google.com.", 1, 1000 + i) for i in range(10)]
    pkts += [make_query(src, dst, f"github.com.", 1, 1010 + i) for i in range(5)]
    return pkts


def build_attack():
    src, dst = "172.30.1.44", "172.30.1.21"
    suspicious = [
        ("aBcDeFgHiJkLmNoPqRsTuVwXyZ123456.attacker.lab.", 16),
        ("xYz9876543210abcdefghij.attacker.lab.", 16),
        ("randomsub999.attacker.lab.", 5),
        ("tunneldata.attacker.lab.", 15),
    ]
    pkts = []
    for i, (qname, qtype) in enumerate(suspicious * 20):
        pkts.append(make_query(src, dst, qname, qtype, 2000 + i * 0.15))
    return pkts


def main():
    normal = PCAPS / "normal_dns.pcap"
    attack = PCAPS / "dnscat2_connect.pcap"
    wrpcap(str(normal), build_normal())
    wrpcap(str(attack), build_attack())
    print(f"[+] {normal} ({len(build_normal())} pkts)")
    print(f"[+] {attack} ({len(build_attack())} pkts)")


if __name__ == "__main__":
    main()
