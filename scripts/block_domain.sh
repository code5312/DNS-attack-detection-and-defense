#!/bin/bash
# attacker.lab 도메인 sinkhole (dnsmasq)
# <random-subdomain>.attacker.lab 패턴 → 0.0.0.0
#
# 사용: sudo ./block_domain.sh [domain]
# 위치: 내부 DNS Resolver / 보안 DNS 장비로 가정

set -euo pipefail

DOMAIN="${1:-attacker.lab}"
CONF_DIR="/etc/dnsmasq.d"
CONF_FILE="${CONF_DIR}/tunnel_block.conf"
PROJECT_CONF="$(dirname "$0")/../rules/dnsmasq_sinkhole.conf"

echo "[*] Domain sinkhole for: $DOMAIN"
echo "address=/${DOMAIN}/0.0.0.0" | sudo tee "$CONF_FILE" > /dev/null

if [ -f "$PROJECT_CONF" ]; then
  echo "[*] Project template: $PROJECT_CONF"
fi

echo "[*] Restart dnsmasq: sudo systemctl restart dnsmasq"
echo "[!] Note: ./dnscat --dns server=IP 직접 지정 시 도메인 차단만으로 부족 → UDP/53 차단 필요"
