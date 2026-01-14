# Smart Home PV Cyber Range - VM-Based Architecture

## Overview

This cyber range is designed as a **red/green/blue** VM-based environment:

- **Green Team VM (10.10.10.10):** runs the Smart Home PV environment as a Docker/Compose stack and exposes the web UI
- **Attacker VM (10.10.10.20):** offensive tooling and scripts (optionally Kali, if your platform provides a Kali base box)
- **Blue Team VM (10.10.10.30):** runs ntopng for network monitoring

## Architecture Components

### 1. Green Team VM (10.10.10.10)
**Base Image:** Debian 12 (x86_64)  
**Flavor:** standard.small  
**Purpose:** Runs the Dockerized Smart Home PV stack and exposes the web UI

#### Services Running:
- **PV Controller Web UI** (Port 80)
- **Modbus TCP** (Port 15002)
- **Mosquitto MQTT Broker** (Port 1883 internal, Port 9001 WebSocket)
- Supporting containers: victim/noise/replayer/telemetry-seeder

#### File Locations:
- Stack directory: `/opt/smart-home-pv/`
- Logs (bind-mounted): `/opt/smart-home-pv/logs/`

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

### 3. Blue Team VM (10.10.10.30)
**Base Image:** Debian 12 (x86_64)  
**Flavor:** standard.small  
**Purpose:** Network monitoring using ntopng

#### Services Running:
- **ntopng** (Port 3000)
  - Web UI: http://10.10.10.30:3000

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
  Green Team     Attacker VM        Blue Team
  (10.10.10.10)  (10.10.10.20)     (10.10.10.30)
```

---

## Attack Surface

### Green Team VM (10.10.10.10)

| Port  | Service        | Protocol | Vulnerabilities                           |
|-------|----------------|----------|-------------------------------------------|
| 80    | PV Controller  | HTTP     | SQLi, Session hijacking, Weak auth       |
| 1883  | MQTT           | MQTT     | No authentication, Message manipulation   |
| 9001  | MQTT WebSocket | WS       | Session token exposure                    |
| 15002 | Modbus TCP     | Modbus   | No authentication, Coil manipulation     |

### Blue Team VM (10.10.10.30)

| Port | Service | Protocol | Notes         |
|------|---------|----------|---------------|
| 3000 | ntopng  | HTTP     | Monitoring UI |

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
**Target:** Port 15002 on Green Team VM  
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
     ├── Green Team VM (10.10.10.10)
     │    └── Smart Home PV stack (Docker/Compose)
       ├── Attacker VM (10.10.10.20)
       │    └── Penetration testing tools
     └── Blue Team VM (10.10.10.30)
        └── ntopng (web UI)
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

### Green Team VM

```bash
# Stack status
cd /opt/smart-home-pv
docker compose ps

# Tail logs
docker compose logs -f --tail=200

# Restart stack
docker compose restart

# Host-level check of exposed ports
ss -lntp | egrep ':(80|9001|15002)'
```

### Blue Team VM

```bash
# Check ntopng + redis
systemctl status ntopng
systemctl status redis-server

# View ntopng logs
journalctl -u ntopng -f
```

### Attacker VM

```bash
# Scan Green Team VM
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
# Check PV stack web UI on Green Team
curl -i http://10.10.10.10/

# Check ntopng on Blue Team
curl -i http://10.10.10.30:3000/
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
