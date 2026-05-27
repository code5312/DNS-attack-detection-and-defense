#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DOMAIN="${1:-attacker.lab}"
APPLY_MODE="${2:-}"
CONF_DIR="/etc/dnsmasq.d"
CONF_FILE="${CONF_DIR}/tunnel_block.conf"
PROJECT_CONF="${ROOT_DIR}/rules/dnsmasq_sinkhole.conf"
DOMAIN_LIST="${ROOT_DIR}/rules/domain_blacklist.txt"

is_valid_domain() {
  local d="$1"
  [[ "$d" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$ ]]
}

apply_single() {
  local d="$1"
  if ! is_valid_domain "$d"; then
    echo "[!] Skip invalid domain: $d"
    return
  fi
  echo "address=/${d}/0.0.0.0"
}

if [[ "$DOMAIN" == "--apply" ]]; then
  APPLY_MODE="--apply"
  DOMAIN=""
fi

if [[ "$APPLY_MODE" == "--apply" ]]; then
  if [[ ! -f "$DOMAIN_LIST" ]]; then
    echo "Domain blacklist file not found: $DOMAIN_LIST"
    exit 1
  fi
  TMP_FILE="$(mktemp "/tmp/dns_sinkhole.XXXXXX")"
  chmod 600 "$TMP_FILE"
  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(echo "$line" | xargs || true)"
    [[ -z "$line" ]] && continue
    apply_single "$line" >> "$TMP_FILE"
  done < "$DOMAIN_LIST"
  sudo mkdir -p "$CONF_DIR"
  sudo cp "$TMP_FILE" "$CONF_FILE"
  rm -f "$TMP_FILE"
  echo "[*] Applied batch sinkhole rules from $DOMAIN_LIST to $CONF_FILE"
else
  if ! is_valid_domain "$DOMAIN"; then
    echo "Invalid domain: $DOMAIN"
    exit 1
  fi
  sudo mkdir -p "$CONF_DIR"
  apply_single "$DOMAIN" | sudo tee "$CONF_FILE" > /dev/null
  echo "[*] Applied single sinkhole for: $DOMAIN"
fi

if [ -f "$PROJECT_CONF" ]; then
  echo "[*] Project sinkhole template: $PROJECT_CONF"
fi

echo "[*] Restart command: sudo systemctl restart dnsmasq"
