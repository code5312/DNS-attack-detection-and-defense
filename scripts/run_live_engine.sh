#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p results

echo "[*] Starting live SOAR engine (defensive monitoring mode)"
python3 engine/live_soar_engine.py
