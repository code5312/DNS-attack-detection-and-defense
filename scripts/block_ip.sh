#!/bin/bash
# iptables 기반 일시 차단
# 사용: sudo ./block_ip.sh <src_ip> [mode]
# mode: kali_input (기본) | ubuntu_output | gateway_forward
#
# Kali 서버에서 Ubuntu 피해자 차단 (실습 권장):
#   sudo ./block_ip.sh 172.30.1.44 kali_input
#
# Ubuntu 로컬 DNS 송신 차단:
#   sudo ./block_ip.sh 172.30.1.44 ubuntu_output
#
# 게이트웨이/Sensor FORWARD 차단:
#   sudo ./block_ip.sh 172.30.1.44 gateway_forward

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

echo "[*] Blocking UDP/53 C2 channel (mode=$MODE) for $SRC_IP"
echo "[*] Command: ${RULE[*]}"
"${RULE[@]}"
echo "$(date -Iseconds) BLOCK $SRC_IP mode=$MODE rule=${RULE[*]}" >> "$LOG_FILE"
echo "[+] Block rule applied. Log: $LOG_FILE"
