#!/bin/bash
set -eu
HOST=${1:-172.20.0.65}
MQTT_HOST=${2:-172.20.0.66}

echo "Testing MQTT path"
MQTT_SES=$(curl -s http://${HOST}/status | python3 -c 'import sys,json; print(json.load(sys.stdin).get("mqtt_session",""))')
if command -v mosquitto_pub >/dev/null 2>&1; then
  mosquitto_pub -h ${MQTT_HOST} -t pv/control -m "{\"command\":\"HALT\",\"session\":\"${MQTT_SES}\"}"
else
  # fallback to server-side sim
  curl -s -X POST http://${HOST}/sim_mqtt -H 'Content-Type: application/json' -d "{\"session\": \"${MQTT_SES}\"}" || true
fi
sleep 1
STATUS=$(curl -s http://${HOST}/status | python3 -c 'import sys,json; print(json.load(sys.stdin).get("status",""))')
echo "status: ${STATUS}"
if [[ "$STATUS" != "HALTED" ]]; then
  echo "MQTT path did not halt the PV"
  exit 1
fi
echo "MQTT path ok"

echo "Testing Modbus path"
# Try pymodbus client if present
if python3 - << 'PY' 2>/dev/null
import importlib,sys
sys.exit(0 if importlib.util.find_spec('pymodbus') else 1)
PY
then
  python3 - <<'PY'
from pymodbus.client.sync import ModbusTcpClient
cli = ModbusTcpClient('${HOST}', port=15002)
cli.connect()
cli.write_coil(1, True, unit=1)
cli.close()
PY
else
  echo "pymodbus not installed, using raw TCP fallback"
  echo "WRITE HALT" | nc ${HOST} 15002 || true
fi
sleep 1
STATUS=$(curl -s http://${HOST}/status | python3 -c 'import sys,json; print(json.load(sys.stdin).get("status",""))')
if [[ "$STATUS" != "HALTED" ]]; then
  echo "Modbus path did not halt the PV"
  exit 1
fi
echo "Modbus path ok"
exit 0
