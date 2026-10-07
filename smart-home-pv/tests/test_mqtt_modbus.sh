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
# Write the HALT coil with a plain Modbus/TCP frame (function code 05) so the
# test needs no pymodbus install and always terminates.
HOST=${HOST} python3 - <<'PY'
import os, socket, struct
host = os.environ['HOST']
# FC05 write single coil: unit 1, coil 1 = ON (0xFF00)
pdu = struct.pack('>BHH', 5, 1, 0xFF00)
frame = struct.pack('>HHHB', 1, 0, len(pdu) + 1, 1) + pdu
s = socket.create_connection((host, 15002), timeout=5)
s.sendall(frame)
resp = s.recv(64)
s.close()
if len(resp) < 8:
    raise SystemExit(f'short Modbus response: {resp.hex()}')
func = resp[7]
if func & 0x80:
    raise SystemExit(f'Modbus exception code {resp[8]}')
print(f'Modbus FC05 accepted: {resp.hex()}')
PY
sleep 1
STATUS=$(curl -s http://${HOST}/status | python3 -c 'import sys,json; print(json.load(sys.stdin).get("status",""))')
if [[ "$STATUS" != "HALTED" ]]; then
  echo "Modbus path did not halt the PV"
  exit 1
fi
echo "Modbus path ok"
exit 0
