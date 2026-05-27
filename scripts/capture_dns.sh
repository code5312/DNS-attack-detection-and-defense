#!/bin/bash
# DNS 트래픽 수집 → pcaps/
# 사용: sudo ./capture_dns.sh eth0 normal_dns

IFACE="${1:-eth0}"
if [[ ! "$IFACE" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
  echo "Invalid interface: $IFACE"
  exit 1
fi
NAME="${2:-dns_capture}"
PCAP_DIR="$(dirname "$0")/../pcaps"
mkdir -p "$PCAP_DIR"
OUT="${PCAP_DIR}/${NAME}_$(date +%Y%m%d_%H%M%S).pcap"

echo "[*] Capturing UDP/53 on $IFACE -> $OUT"
sudo tcpdump -i "$IFACE" -nn udp port 53 -w "$OUT"
