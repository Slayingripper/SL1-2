# Smart Home PV Challenge - CyberRangeCZ Training

This repository contains the Training Definition and Sandbox Definition for the Smart Home PV Challenge, adapted for the CyberRangeCZ Platform.

## Architecture

This cyber range uses a **VM-based architecture** with three separate virtual machines:

1. **Blue Team VM** (`blueteam` - 10.10.10.10): Hosts the PV Controller, MQTT broker, and victim simulator
2. **Attacker VM** (`attacker` - 10.10.10.20): Contains penetration testing tools and attack scripts
3. **Admin Dashboard VM** (`admin-dashboard` - 10.10.10.30): Hosts the React-based monitoring interface

## Structure

- `training.json`: Defines the training levels, flags, and content
- `topology.yml`: Defines the sandbox topology (3 VMs + router)
- `provisioning/playbook.yml`: Main Ansible playbook orchestrating all roles
- `provisioning/roles/`: Ansible roles for each VM:
  - `blueteam/`: Provisions the PV Controller and MQTT services
  - `attacker/`: Provisions penetration testing tools
  - `admin-dashboard/`: Provisions the React dashboard with Nginx
- `provisioning/files/smart-home-pv/`: The challenge source code
- `variables.yml`: APG variables for flags and passwords

## Deployment

1. Push this repository to your CyberRangeCZ Git instance
2. Create a new **Training Definition** in the platform using this repository
3. Create a **Sandbox Definition** (if needed separately, or the platform might use the same repo for both if configured)
4. Create a Training Instance and run it
5. The platform will provision 3 VMs and configure them using Ansible

## Network Topology

```
Internet (100.100.100.0/24)
    |
  Router (10.10.10.1)
    |
Game Network (10.10.10.0/24)
    |
    +-- Blue Team VM (10.10.10.10)
    |   - PV Controller (HTTP: 80, Modbus: 15002)
    |   - MQTT Broker (Port: 1883, WebSocket: 9001)
    |   - Victim Simulator
    |
    +-- Attacker VM (10.10.10.20)
    |   - Penetration testing tools
    |   - Attack scripts
    |
    +-- Admin Dashboard VM (10.10.10.30)
        - React monitoring dashboard (HTTP: 80)
```

## Access

### Attacker Machine
SSH into the attacker VM:

```bash
ssh attacker@<attacker-vm-ip>
# Or from within the network:
ssh attacker@10.10.10.20
```
Password: `attacker`

Available tools in `/home/attacker/tools/`:
- `attacker_modbus.py`: Modbus attack scripts
- `demo_attacks.sh`: Automated attack demonstrations
- `nmap`, `hydra`, `nikto`, `tcpdump`, `scapy`, and more

### Blue Team Infrastructure
The PV Controller and services run directly on the VM (not in Docker):

```bash
# SSH to blue team VM
ssh debian@<blueteam-vm-ip>

# Check service status
systemctl status pv-controller
systemctl status mosquitto
systemctl status victim-simulator

# View logs
journalctl -u pv-controller -f
tail -f /opt/pv-controller/logs/security_events.json
```

Services:
- **PV Controller API**: http://10.10.10.10:80
- **Modbus TCP**: Port 15002
- **MQTT Broker**: Port 1883 (internal), Port 9001 (WebSocket)

### Admin Dashboard
Access the monitoring dashboard:

```bash
# Via browser
http://10.10.10.30

# Or from your local machine (if port forwarded)
http://<admin-dashboard-vm-ip>
```

The dashboard provides:
- Real-time PV system monitoring
- Security event alerts
- Modbus/MQTT traffic visualization
- Incident response tools

## Training Scenario

This cyber range simulates a Smart Home Photovoltaic (PV) Controller system with realistic attack scenarios:

1. **Reconnaissance**: Scan the network to discover services
2. **MQTT Hijacking**: Intercept and manipulate MQTT messages
3. **Modbus Exploitation**: Attack the industrial control protocol
4. **Web Application Attacks**: Exploit the admin dashboard
5. **Incident Response**: Detect and respond to attacks from the Blue Team perspective

## Development Notes

### Converting from Docker to VMs

This project was originally Docker-based and has been converted to use separate VMs:
- **Original**: Single VM running Docker containers
- **Current**: Three VMs with native service installations

Benefits:
- More realistic network segmentation
- Better isolation between attacker and defender
- Easier to monitor network traffic
- More representative of real infrastructure

### Service Management

Each VM runs services natively:
- **Blue Team**: systemd services for PV controller and victim simulator
- **Attacker**: SSH daemon with pre-installed tools
- **Admin Dashboard**: Nginx serving React SPA
