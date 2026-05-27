#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RULES="$ROOT/rules/dns_tunnel.rules"
OUT_DIR="$ROOT/results"
PCAP="${1:-$ROOT/pcaps/dnscat2_connect.pcap}"
SNORT_CONF="${2:-}"

mkdir -p "$OUT_DIR"

if [[ -z "$SNORT_CONF" ]]; then
  echo "Usage: sudo bash scripts/run_snort.sh <pcap_path> <snort_conf_path>"
  echo "Example: sudo bash scripts/run_snort.sh $PCAP /etc/snort/snort.conf"
  exit 1
fi

echo "[*] Running Snort"
echo "    pcap : $PCAP"
echo "    rules: $RULES"
echo "    conf : $SNORT_CONF"

sudo snort -r "$PCAP" -A fast -l "$OUT_DIR" -c "$SNORT_CONF"
