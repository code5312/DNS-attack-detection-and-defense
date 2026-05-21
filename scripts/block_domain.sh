#!/bin/bash
set -euo pipefail

DOMAIN="${1:-attacker.lab}"
CONF_DIR="/etc/dnsmasq.d"
CONF_FILE="${CONF_DIR}/tunnel_block.conf"
PROJECT_CONF="$(dirname "$0")/../rules/dnsmasq_sinkhole.conf"

if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Invalid domain: $DOMAIN"
  exit 1
fi

echo "[*] Domain sinkhole for: $DOMAIN"
echo "address=/${DOMAIN}/0.0.0.0" | sudo tee "$CONF_FILE" > /dev/null

if [ -f "$PROJECT_CONF" ]; then
  echo "[*] Project sinkhole template: $PROJECT_CONF"
fi

echo "[*] Restart command: sudo systemctl restart dnsmasq"
