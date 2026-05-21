#!/bin/bash
set -euo pipefail

SRC_IP="${1:?Usage: unblock_ip.sh <src_ip> [mode]}"
MODE="${2:-kali_input}"
LOG_FILE="$(dirname "$0")/../results/block_rules.log"

case "$MODE" in
  kali_input)
    RULE=(iptables -D INPUT -s "$SRC_IP" -p udp --dport 53 -j DROP)
    CHECK=(iptables -C INPUT -s "$SRC_IP" -p udp --dport 53 -j DROP)
    ;;
  ubuntu_output)
    RULE=(iptables -D OUTPUT -p udp --dport 53 -j DROP)
    CHECK=(iptables -C OUTPUT -p udp --dport 53 -j DROP)
    ;;
  gateway_forward)
    RULE=(iptables -D FORWARD -s "$SRC_IP" -p udp --dport 53 -j DROP)
    CHECK=(iptables -C FORWARD -s "$SRC_IP" -p udp --dport 53 -j DROP)
    ;;
  *)
    echo "Unknown mode: $MODE"
    exit 1
    ;;
esac

if ! "${CHECK[@]}" 2>/dev/null; then
  echo "[*] No existing rule for $SRC_IP (mode=$MODE)"
  exit 0
fi

echo "[*] Removing rule: ${RULE[*]}"
"${RULE[@]}"
echo "$(date -Iseconds) UNBLOCK $SRC_IP mode=$MODE rule=${RULE[*]}" >> "$LOG_FILE"
echo "[+] Unblock complete"
