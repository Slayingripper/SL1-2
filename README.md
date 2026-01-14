# Smart Home PV Challenge - CyberRangeCZ Training

This repository contains the Training Definition and Sandbox Definition for the Smart Home PV Challenge, adapted for the CyberRangeCZ Platform.

## Architecture

This cyber range uses a **VM-based architecture** with three separate virtual machines:

1. **Green Team VM** (`green-team` - 10.10.10.10): Runs the Smart Home PV Docker stack and exposes the web UI
2. **Attacker VM** (`attacker` - 10.10.10.20): Contains penetration testing tools and attack scripts
3. **Blue Team VM** (`blue-team` - 10.10.10.30): Runs ntopng for network monitoring

## Structure

- `training.json`: Defines the training levels, flags, and content
- `topology.yml`: Defines the sandbox topology (3 VMs + router)
- `provisioning/playbook.yml`: Main Ansible playbook orchestrating all roles
- `provisioning/roles/`: Ansible roles for each VM:
  - `green-team/`: Runs the Dockerized Smart Home PV stack
  - `attacker/`: Provisions penetration testing tools
  - `blue-team/`: Installs and configures ntopng
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
    +-- Green Team VM (10.10.10.10)
    |   - PV stack web UI (HTTP: 80)
    |   - Modbus TCP (Port: 15002)
    |   - MQTT Broker (Port: 1883, WebSocket: 9001)
    |
    +-- Attacker VM (10.10.10.20)
    |   - Penetration testing tools
    |   - Attack scripts
    |
    +-- Blue Team VM (10.10.10.30)
      - ntopng (HTTP: 3000)
```

## Access

CyberRangeCZ management access (web console / SSH) uses the VM management user from `topology.yml`.
This repository's provisioning enforces the intended passwords on the VMs based on `variables.yml` (defaults: `cyberrange123` for Debian VMs, `attacker` for the attacker VM).

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

### Green Team (PV Stack)
The Smart Home PV stack runs on the green-team VM and is exposed via the VM IP:

- Web UI: http://10.10.10.10/

### Blue Team (Monitoring)
The blue-team VM runs ntopng:

- ntopng UI: http://10.10.10.30:3000

### Notes
The Docker stack source lives in `provisioning/files/smart-home-pv/` and is deployed to `/opt/smart-home-pv` on the green-team VM.

Green-team service management:

```bash
ssh debian@<green-team-vm-ip>
cd /opt/smart-home-pv
docker compose ps
docker compose logs -f --tail=200
```

Green-team exposed ports:
- HTTP web UI: `http://10.10.10.10/`
- Modbus TCP: `10.10.10.10:15002`
- MQTT WebSocket: `ws://10.10.10.10:9001`

## Training Scenario

This cyber range simulates a Smart Home Photovoltaic (PV) Controller system with realistic attack scenarios:

1. **Reconnaissance**: Scan the network to discover services
2. **MQTT Hijacking**: Intercept and manipulate MQTT messages
3. **Modbus Exploitation**: Attack the industrial control protocol
4. **Web Application Attacks**: Exploit the admin dashboard
5. **Incident Response**: Detect and respond to attacks from the Blue Team perspective

## Development Notes

### Converting from Docker to VMs

This project is designed as a red/green/blue VM-based cyber range:
- **Attacker VM**: offensive tooling and scripts
- **Green Team VM**: runs the Dockerized Smart Home PV stack
- **Blue Team VM**: runs ntopng to monitor the network

Benefits:
- More realistic network segmentation
- Better isolation between attacker and defender
- Easier to monitor network traffic
- More representative of real infrastructure

### Service Management

Each VM has a clear purpose:
- **Green Team**: Docker/Compose stack under `/opt/smart-home-pv`
- **Attacker**: tools under `/home/attacker/tools/`
- **Blue Team**: ntopng UI on `http://10.10.10.30:3000`
