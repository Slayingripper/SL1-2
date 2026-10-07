#!/usr/bin/env bash
set -euo pipefail

# Smoke test for smart-home-pv challenge
BASE_DIR=$(cd "$(dirname "$0")/.." && pwd)
COMPOSE_FILE="$BASE_DIR/docker-compose.yml"

function cleanup() {
  docker compose -f "$COMPOSE_FILE" down --remove-orphans || true
}
trap cleanup EXIT

# Build & start
cd "$BASE_DIR"
docker compose -f "$COMPOSE_FILE" build --parallel

echo "Starting challenge stack..."
docker compose -f "$COMPOSE_FILE" up -d

# Wait for PV controller to be available
for i in {1..20}; do
  sleep 2
  if curl -sSf http://172.20.0.65/ >/dev/null 2>&1; then
    echo "controller is up"
    break
  fi
  if [ "$i" -eq 20 ]; then
    echo "controller did not start in time"
    exit 2
  fi
done

# Check dashboard page
echo "Checking dashboard UI..."
if ! curl -sSf http://172.20.0.65/admin >/dev/null; then
  echo "dashboard not reachable"
  exit 3
fi

echo "Check admin/mqtt_data for telemetry; wait up to 30 seconds for data to appear"
for i in {1..30}; do
  sleep 1
  cnt=$(curl -s http://172.20.0.65/admin/mqtt_data | jq -r 'length' || echo 0)
  echo "mqtt points: $cnt"
  if [ "$cnt" -gt 0 ]; then
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "No telemetry data detected"
    exit 4
  fi
done

# Test admin publish endpoint: push telemetry and validate it's in the series
echo "Testing admin/publish_telemetry"
curl -s -X POST -H 'Content-Type: application/json' -d '{"power":12345}' http://172.20.0.65/admin/publish_telemetry || true
sleep 2
# The controller republishes its own simulated reading every few seconds, so the
# injected point is not necessarily the newest one - look for it in the tail.
recent=$(curl -s http://172.20.0.65/admin/mqtt_data | jq -c '.[-10:]')
echo "Recent MQTT points: $recent"
if ! echo "$recent" | jq -e 'map(select(.power == 12345)) | length > 0' >/dev/null; then
  echo "published telemetry not found in admin/mqtt_data"
  exit 5
fi

# Try to download pcap
if curl -sSf http://172.20.0.65/logs/traffic.pcap -o /tmp/traffic.pcap; then
  echo "pcap downloaded, size: $(stat -c%s /tmp/traffic.pcap)"
else
  echo "pcap not found or could not be downloaded"
fi

echo "Smoke tests passed"
