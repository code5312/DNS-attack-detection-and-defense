#!/bin/bash
# Snort 룰 테스트 (rules/dns_tunnel.rules)
# sudo snort -r pcaps/dnscat2_connect.pcap -c snort.conf -A fast -l results/

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RULES="$ROOT/rules/dns_tunnel.rules"
LOG="$ROOT/results/snort_alerts.log"

echo "[*] Snort rules: $RULES"
echo "[*] Alert log:   $LOG"
echo ""
echo "pcap 테스트 예:"
echo "  sudo snort -r $ROOT/pcaps/dnscat2_connect.pcap \\"
echo "    -A fast -l $ROOT/results -c <snort.conf including $RULES>"
