#!/bin/bash
# iptables 차단 해제
# 사용: sudo ./unblock_ip.sh <src_ip> [mode]

set -euo pipefail

SRC_IP="${1:?Usage: unblock_ip.sh <src_ip> [mode]}"
MODE="${2:-kali_input}"

case "$MODE" in
  kali_input)
    RULE=(iptables -D INPUT -s "$SRC_IP" -p udp --dport 53 -j DROP)
    ;;
  ubuntu_output)
    RULE=(iptables -D OUTPUT -p udp --dport 53 -j DROP)
    ;;
  gateway_forward)
    RULE=(iptables -D FORWARD -s "$SRC_IP" -p udp --dport 53 -j DROP)
    ;;
  *)
    echo "Unknown mode: $MODE"
    exit 1
    ;;
esac

echo "[*] Removing rule: ${RULE[*]}"
"${RULE[@]}" 2>/dev/null || echo "[!] Rule may not exist"
echo "[+] Unblock complete for $SRC_IP"
