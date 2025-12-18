#!/bin/bash
set -euo pipefail

# Build and start services
PWD=$(dirname "$0")
cd "$PWD"

echo "[*] Building and starting services..."
docker compose -f docker-compose.yml up --build -d

echo "[*] Running attacker demo in the attacker container (sqlmap, modbus, mqtt)"
docker compose -f docker-compose.yml run --rm attacker bash -c "/home/attacker/tools/demo_attacks.sh 172.20.0.65 172.20.0.66"

echo "[*] Test complete. Check logs or flag endpoints to confirm expected behavior."
