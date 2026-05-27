#!/bin/bash
set -euo pipefail

SRC_IP="${1:?Usage: block_ip.sh <src_ip> [mode]}"
MODE="${2:-kali_input}"
LOG_FILE="$(dirname "$0")/../results/block_rules.log"
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

if [[ ! "$SRC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Invalid IPv4 format: $SRC_IP"
  exit 1
fi
IFS='.' read -r o1 o2 o3 o4 <<< "$SRC_IP"
for oct in "$o1" "$o2" "$o3" "$o4"; do
  if (( oct < 0 || oct > 255 )); then
    echo "Invalid IPv4 octet in: $SRC_IP"
    exit 1
  fi
done

case "$MODE" in
  kali_input)
    RULE=(iptables -A INPUT -s "$SRC_IP" -p udp --dport 53 -j DROP)
    CHECK=(iptables -C INPUT -s "$SRC_IP" -p udp --dport 53 -j DROP)
    ;;
  ubuntu_output)
    RULE=(iptables -A OUTPUT -s "$SRC_IP" -p udp --dport 53 -j DROP)
    CHECK=(iptables -C OUTPUT -s "$SRC_IP" -p udp --dport 53 -j DROP)
    ;;
  gateway_forward)
    RULE=(iptables -A FORWARD -s "$SRC_IP" -p udp --dport 53 -j DROP)
    CHECK=(iptables -C FORWARD -s "$SRC_IP" -p udp --dport 53 -j DROP)
    ;;
  *)
    echo "Unknown mode: $MODE"
    exit 1
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
