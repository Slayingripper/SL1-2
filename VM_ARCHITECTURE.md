# Smart Home PV Cyber Range - VM-Based Architecture

## Overview

This cyber range has been converted from a Docker-based architecture to a VM-based architecture for more realistic network segmentation and better representation of real-world infrastructure.

## Architecture Components

### 1. Blue Team VM (10.10.10.10)
**Base Image:** Debian 12 (x86_64)  
**Flavor:** standard.small  
**Purpose:** Production infrastructure hosting PV controller services

#### Services Running:
- **PV Controller** (Port 80)
  - Python Flask application
  - Manages solar panel operations
  - Provides REST API and web interface
  - Systemd service: `pv-controller.service`
  
- **Mosquitto MQTT Broker** (Ports 1883, 9001)
  - Message broker for IoT device communication
  - Port 1883: Standard MQTT
  - Port 9001: WebSocket for web clients
  - Systemd service: `mosquitto.service`
  
- **Modbus TCP Server** (Port 15002)
  - Industrial Control System (ICS) protocol
  - Embedded in PV controller application
  - Used for inverter control
  
- **Victim Simulator** (background)
  - Node.js application
  - Simulates legitimate user behavior
  - Periodically accesses PV controller
  - Systemd service: `victim-simulator.service`

#### File Locations:
- Application: `/opt/pv-controller/`
- Logs: `/opt/pv-controller/logs/`
- Configuration: `/opt/pv-controller/mosquitto-config/`

#### Security Events Logged:
- Failed login attempts
- Suspicious API calls
- Blocked IPs
- MQTT/Modbus anomalies
- Packet captures (PCAP files)

---

### 2. Attacker VM (10.10.10.20)
**Base Image:** Debian 12 (x86_64)  
**Flavor:** standard.small  
**Purpose:** Red team operations and penetration testing

#### Pre-installed Tools:
- **Network Scanning:** nmap, netcat
- **Password Attacks:** hydra
- **Web Scanning:** nikto
- **Traffic Analysis:** tcpdump, scapy
- **Protocol Tools:** pymodbus, mosquitto-clients
- **Exploitation:** dsniff, ettercap, arpspoof
- **Development:** python3, pip

#### Custom Scripts (~/tools/):
- `attacker_modbus.py`: Modbus TCP attack scripts
- `demo_attacks.sh`: Automated attack demonstrations
- Scan results for reference

#### User Account:
- Username: `attacker`
- Password: `attacker`
- Sudo access: enabled

#### SSH Access:
- Port: 22
- Password authentication: enabled

---

### 3. Admin Dashboard VM (10.10.10.30)
**Base Image:** Ubuntu Noble (x86_64)  
**Flavor:** standard.small  
**Purpose:** Security operations center monitoring interface

#### Services Running:
- **Nginx Web Server** (Port 80)
  - Serves React SPA
  - Proxies API requests to Blue Team VM
  - Systemd service: `nginx.service`

#### Dashboard Features:
- Real-time PV system monitoring
- Security event visualization
- MQTT message stream
- Modbus traffic analysis
- Incident response tools
- Container switching (legacy feature)

#### File Locations:
- Source: `/opt/admin-dashboard/`
- Built files: `/opt/admin-dashboard/dist/`
- Nginx config: `/etc/nginx/sites-available/admin-dashboard`

#### Environment:
- PV Controller API: http://10.10.10.10
- MQTT Broker: ws://10.10.10.10:9001

---

### 4. Router VM (10.10.10.1)
**Base Image:** Debian 12 (x86_64)  
**Flavor:** standard.small  
**Purpose:** Network gateway and routing

#### Networks:
- **WAN:** 100.100.100.0/24 (Internet connection)
- **LAN:** 10.10.10.0/24 (Game network)

#### Routing:
- Connects all VMs to the game network
- Provides internet access for package installation
- Allows traffic monitoring at network boundary

---

## Network Topology

```
                    Internet
                        |
                 [100.100.100.0/24]
                        |
                   Router VM
                  (10.10.10.1)
                        |
              [Game Network: 10.10.10.0/24]
                        |
        +---------------+----------------+
        |               |                |
   Blue Team      Attacker VM      Admin Dashboard
  (10.10.10.10)  (10.10.10.20)     (10.10.10.30)
```

---

## Attack Surface

### Blue Team VM (10.10.10.10)

| Port  | Service        | Protocol | Vulnerabilities                           |
|-------|----------------|----------|-------------------------------------------|
| 80    | PV Controller  | HTTP     | SQLi, Session hijacking, Weak auth       |
| 1883  | MQTT           | MQTT     | No authentication, Message manipulation   |
| 9001  | MQTT WebSocket | WS       | Session token exposure                    |
| 15002 | Modbus TCP     | Modbus   | No authentication, Coil manipulation     |

### Admin Dashboard VM (10.10.10.30)

| Port | Service | Protocol | Vulnerabilities                    |
|------|---------|----------|------------------------------------|
| 80   | Nginx   | HTTP     | XSS, CSRF, Exposed admin functions |

---

## Attack Scenarios

### 1. Network Reconnaissance
**Objective:** Discover services and open ports  
**Tools:** nmap, netcat  
**Target:** All VMs on 10.10.10.0/24

### 2. MQTT Hijacking
**Objective:** Intercept and manipulate MQTT messages  
**Tools:** ARP spoofing (ettercap, arpspoof), mosquitto-clients  
**Steps:**
1. ARP spoof between victim and MQTT broker
2. Subscribe to `pv/status` topic
3. Extract session token
4. Publish malicious command to `pv/control`

### 3. Modbus Exploitation
**Objective:** Manipulate industrial control coils  
**Tools:** pymodbus, custom scripts  
**Target:** Port 15002 on Blue Team VM  
**Steps:**
1. Connect to Modbus TCP server
2. Read holding registers
3. Write to coils to stop production

### 4. Web Application Attacks
**Objective:** Exploit SQL injection and XSS  
**Tools:** sqlmap, Burp Suite, custom scripts  
**Targets:**
- `/api/login` - SQL injection
- `/api/admin/devices` - Stored XSS
- `/api/hub/command` - Command injection

### 5. Session Hijacking
**Objective:** Steal and reuse authentication tokens  
**Tools:** tcpdump, Wireshark  
**Methods:**
- MITM attack on victim traffic
- Capture HTTP headers with session tokens
- Replay tokens to authenticate

### 6. Phishing (Simulated)
**Objective:** Credential harvesting  
**Tools:** Custom phishing server  
**Steps:**
1. Host phishing page
2. Victim simulator accesses page
3. Capture credentials
4. Use credentials for privileged access

---

## Deployment Differences: Docker vs VM

### Docker-Based (Original)

```
Single VM (game-server)
  └── Docker Engine
       ├── pv-controller (172.20.0.65)
       ├── mosquitto (172.20.0.66)
       ├── attacker (172.20.0.70) - SSH on port 2224
       ├── victim (172.20.0.72)
       ├── noise (172.20.0.71)
       ├── replayer (172.20.0.74)
       └── telemetry-seeder (172.20.0.73)
```

**Characteristics:**
- All services on one VM
- Internal Docker network (172.20.0.0/24)
- Port forwarding for external access
- Containers share kernel

### VM-Based (Current)

```
Router (10.10.10.1)
  └── Game Network (10.10.10.0/24)
       ├── Blue Team VM (10.10.10.10)
       │    ├── PV Controller (systemd)
       │    ├── Mosquitto (systemd)
       │    └── Victim Simulator (systemd)
       ├── Attacker VM (10.10.10.20)
       │    └── Penetration testing tools
       └── Admin Dashboard VM (10.10.10.30)
            └── Nginx + React SPA
```

**Characteristics:**
- Three separate VMs
- True network segmentation
- Native service installation (systemd)
- Individual VM management
- More realistic infrastructure

---

## Benefits of VM-Based Architecture

1. **Realistic Network Segmentation**
   - True layer-3 routing
   - Real network packets between systems
   - Authentic ARP spoofing scenarios

2. **Better Isolation**
   - Complete OS separation
   - Independent kernels
   - Realistic privilege boundaries

3. **Easier Monitoring**
   - Network traffic visible at router
   - Clear packet capture points
   - Distinct log files per system

4. **Educational Value**
   - More representative of production environments
   - Real service management (systemd)
   - Actual network configuration

5. **Scalability**
   - Easy to add more VMs
   - Can simulate larger networks
   - Independent resource allocation

---

## Service Management Commands

### Blue Team VM

```bash
# Check PV controller status
systemctl status pv-controller

# View PV controller logs
journalctl -u pv-controller -f

# Restart PV controller
systemctl restart pv-controller

# Check MQTT broker
systemctl status mosquitto

# View security events
tail -f /opt/pv-controller/logs/security_events.json

# Analyze packet captures
tcpdump -r /opt/pv-controller/logs/traffic.pcap
```

### Admin Dashboard VM

```bash
# Check Nginx status
systemctl status nginx

# View Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Restart Nginx
systemctl restart nginx

# Rebuild dashboard (if modified)
cd /opt/admin-dashboard
npm run build
```

### Attacker VM

```bash
# Scan Blue Team VM
nmap -sV -p- 10.10.10.10

# Test MQTT connection
mosquitto_sub -h 10.10.10.10 -t 'pv/#' -v

# Run attack scripts
cd ~/tools
./demo_attacks.sh

# Modbus attack
python3 attacker_modbus.py --target 10.10.10.10 --port 15002
```

---

## Troubleshooting

### Service Not Starting

```bash
# Check service status
systemctl status <service-name>

# View detailed logs
journalctl -xeu <service-name>

# Check if port is already in use
netstat -tlnp | grep <port>
```

### Network Connectivity Issues

```bash
# Verify IP configuration
ip addr show

# Test connectivity
ping 10.10.10.10
ping 10.10.10.20
ping 10.10.10.30

# Check routing
ip route show

# Trace route
traceroute 10.10.10.10
```

### Dashboard Not Loading

```bash
# Check if built files exist
ls -la /opt/admin-dashboard/dist/

# Verify Nginx configuration
nginx -t

# Check Nginx is running
systemctl status nginx

# Test backend API
curl http://10.10.10.10/api/health
```

---

## Security Considerations

### Intentional Vulnerabilities

The following vulnerabilities are **intentionally present** for training purposes:

1. **No MQTT Authentication** - Allows message interception
2. **No Modbus Security** - Enables ICS attacks
3. **Weak Session Management** - Facilitates session hijacking
4. **SQL Injection** - In admin login endpoint
5. **Stored XSS** - In device management
6. **No HTTPS** - All traffic in cleartext
7. **Hardcoded Credentials** - In victim simulator

### Do NOT Deploy in Production

This cyber range is designed for **educational purposes only**. The intentional security flaws make it unsuitable for any production use.

---

## License

See the main repository LICENSE file for licensing information.
