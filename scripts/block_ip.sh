#!/bin/bash
set -euo pipefail

SRC_IP="${1:?Usage: block_ip.sh <src_ip> [mode]}"
MODE="${2:-kali_input}"
LOG_FILE="$(dirname "$0")/../results/block_rules.log"
mkdir -p "$(dirname "$LOG_FILE")"

case "$MODE" in
  kali_input)
    RULE=(iptables -A INPUT -s "$SRC_IP" -p udp --dport 53 -j DROP)
    ;;
  ubuntu_output)
    RULE=(iptables -A OUTPUT -p udp --dport 53 -j DROP)
    ;;
  gateway_forward)
    RULE=(iptables -A FORWARD -s "$SRC_IP" -p udp --dport 53 -j DROP)
    ;;
  *)
    echo "Unknown mode: $MODE"
    exit 1
    ;;
esac

case "$MODE" in
  kali_input)
    CHECK=(iptables -C INPUT -s "$SRC_IP" -p udp --dport 53 -j DROP)
    ;;
  ubuntu_output)
    CHECK=(iptables -C OUTPUT -p udp --dport 53 -j DROP)
    ;;
  gateway_forward)
    CHECK=(iptables -C FORWARD -s "$SRC_IP" -p udp --dport 53 -j DROP)
    ;;
esac

if "${CHECK[@]}" 2>/dev/null; then
  echo "[*] Rule already exists for $SRC_IP (mode=$MODE)"
  exit 0
fi

echo "[*] Applying block rule: ${RULE[*]}"
"${RULE[@]}"
echo "$(date -Iseconds) BLOCK $SRC_IP mode=$MODE rule=${RULE[*]}" >> "$LOG_FILE"
echo "[+] Block rule applied"
