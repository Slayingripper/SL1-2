# Migration Guide: Docker to VM-Based Architecture

This document explains the migration from Docker-based to VM-based architecture and what has changed.

## Summary of Changes

### What Changed

1. **Infrastructure**
   - **Before:** Single VM running Docker containers
  - **After:** Three separate VMs (green-team, attacker, blue-team)

2. **Networking**
   - **Before:** Docker network (172.20.0.0/24) with port forwarding
   - **After:** Real network (10.10.10.0/24) with VM-to-VM communication

3. **Service Deployment**
   - **Before:** Docker Compose orchestration
  - **After:** Docker Compose on the Green Team VM, plus separate Attacker/Blue Team VMs

4. **Access Methods**
   - **Before:** SSH to game-server, then access container on port 2224
   - **After:** Direct SSH to attacker VM (10.10.10.20)

### What Stayed the Same

1. **Application Code**
   - PV controller Python code unchanged
   - Admin dashboard React code unchanged
   - Attacker tools and scripts unchanged

2. **Attack Scenarios**
   - All attack vectors remain valid
   - Same vulnerabilities are present
   - Training objectives unchanged

3. **User Experience**
   - Same tools available on attacker machine
   - Same web interfaces
   - Same flags and challenges

## File Structure Changes

### Old Structure (Docker-based)
```
provisioning/
  playbook.yml              # Single playbook for game-server
  files/
    smart-home-pv/
      docker-compose.yml    # Orchestrated all containers
      Dockerfile            # PV controller image
      tools/
        attacker/Dockerfile # Attacker container
        victim/Dockerfile   # Victim container
```

### New Structure (VM-based)
```
provisioning/
  playbook.yml              # Main playbook (calls all roles)
  roles/
    green-team/
      tasks/main.yml        # Docker + Compose deployment of PV stack
      handlers/main.yml
    attacker/
      tasks/main.yml        # Attacker tools installation
      handlers/main.yml     # SSH restart handler
    blue-team/
      tasks/main.yml        # ntopng + redis setup
      handlers/main.yml
  files/
    smart-home-pv/          # Application source (still present)
```

## Component Mapping

### PV Controller Container → Green Team VM

**Old (Docker):**
```yaml
services:
  pv-controller:
    build: .
    image: scl-challenge-smart-home-pv
    container_name: scl-challenge-smart-home-pv
    networks:
      playground-net:
        ipv4_address: 172.20.0.65
    ports:
      - "8081:80"
      - "15002:15002"
```

**New (VM):**
```yaml
# topology.yml
hosts:
  - name: green-team
    base_box:
      image: debian-12-x86_64
    flavor: standard.small
    ip: 10.10.10.10

# Deployed as Docker Compose stack
/opt/smart-home-pv/docker-compose.yml
```

### Attacker Container → Attacker VM

**Old (Docker):**
```yaml
services:
  attacker:
    build: ./tools/attacker
    container_name: scl-challenge-smart-home-pv-attacker
    networks:
      playground-net:
        ipv4_address: 172.20.0.70
    # SSH port forwarded to 2224 on host
```

**New (VM):**
```yaml
# topology.yml
hosts:
  - name: attacker
    base_box:
      image: debian-12-x86_64
    flavor: standard.small
    ip: 10.10.10.20

# Native SSH on port 22
# Direct network access to other VMs
```

### Mosquitto Container → Green Team VM (container)

**Old (Docker):**
```yaml
services:
  mosquitto:
    image: eclipse-mosquitto:2.0
    container_name: scl-challenge-mosquitto
    networks:
      playground-net:
        ipv4_address: 172.20.0.66
    ports:
      - "9001:9001"
```

**New (VM):**
- Still runs as the `mosquitto` container inside the Green Team VM's Docker/Compose stack.

## Network Translation

### IP Address Mapping

| Component | Docker IP | VM IP |
|-----------|-----------|-------|
| PV Controller | 172.20.0.65 | 10.10.10.10 |
| MQTT Broker | 172.20.0.66 | 10.10.10.10 (same VM) |
| Attacker | 172.20.0.70 | 10.10.10.20 |
| Victim | 172.20.0.72 | 10.10.10.10 (same VM) |
| Monitoring (ntopng) | N/A | 10.10.10.30 |

### Port Mapping

| Service | Docker | VM |
|---------|--------|-----|
| PV Controller Web | game-server:8081 | 10.10.10.10:80 |
| ntopng | N/A | 10.10.10.30:3000 |
| MQTT WebSocket | game-server:9001 | 10.10.10.10:9001 |
| Modbus TCP | game-server:15002 | 10.10.10.10:15002 |
| Attacker SSH | game-server:2224 | 10.10.10.20:22 |

## Updated Access Instructions

### Accessing the Attacker Machine

**Old Method:**
```bash
# SSH to game-server first
ssh user@<game-server-ip>

# Then SSH to attacker container
ssh -p 2224 attacker@localhost
```

**New Method:**
```bash
# Direct SSH to attacker VM
ssh attacker@<attacker-vm-ip>

# Or using the internal IP
ssh attacker@10.10.10.20
```

### Accessing Web Interfaces

**Old URLs:**
```
PV Controller:     http://<game-server-ip>:8081
Admin Dashboard:   http://<game-server-ip>:8081 (same interface)
```

**New URLs:**
```
PV Controller:     http://10.10.10.10/
ntopng:            http://10.10.10.30:3000/
```

## Service Management Changes

### Starting Services

**Old (Docker):**
```bash
# On game-server
cd /opt/smart-home-pv
docker-compose up -d

# Check status
docker ps

# View logs
docker logs scl-challenge-smart-home-pv
```

**New (VM):**
```bash
# On green-team VM
ssh debian@10.10.10.10
cd /opt/smart-home-pv
docker compose up -d --build

# Check status
docker compose ps

# View logs
docker compose logs -f --tail=200
```

### Troubleshooting

**Old (Docker):**
```bash
# Enter container
docker exec -it scl-challenge-smart-home-pv bash

# Restart container
docker restart scl-challenge-smart-home-pv

# View network
docker network inspect playground-net
```

**New (VM):**
```bash
# Green Team troubleshooting
ssh debian@10.10.10.10
cd /opt/smart-home-pv
docker compose restart

# Blue Team troubleshooting (ntopng)
ssh debian@10.10.10.30
sudo systemctl restart ntopng
sudo journalctl -u ntopng -n 100 --no-pager
```

## Attack Script Updates

Most attack scripts require minimal changes. Update target IPs:

**Old script:**
```python
# attacker_modbus.py
TARGET_HOST = "pv-controller"  # Docker hostname
TARGET_PORT = 15002
```

**New script:**
```python
# attacker_modbus.py
TARGET_HOST = "10.10.10.10"  # VM IP
TARGET_PORT = 15002
```

**Old MQTT connection:**
```bash
mosquitto_sub -h mosquitto -t 'pv/#'
```

**New MQTT connection:**
```bash
mosquitto_sub -h 10.10.10.10 -t 'pv/#'
```

## Monitoring (Blue Team)

The Blue Team VM provides network monitoring via ntopng:

- URL: `http://10.10.10.30:3000/`
- Redis is required and is started by the provisioning role.

## Removed Components

The following is no longer used:

1. **Attacker container** - replaced by a dedicated Attacker VM

## Testing the Migration

### Verify Green Team VM

```bash
ssh debian@10.10.10.10

cd /opt/smart-home-pv
docker compose ps

# Test web UI
curl -i http://localhost/

# Test Modbus (host port forwarded to container)
python3 -c "from pymodbus.client import ModbusTcpClient; c = ModbusTcpClient('127.0.0.1', 15002); print(c.connect())"
```

### Verify Attacker VM

```bash
ssh attacker@10.10.10.20

# Check tools
which nmap hydra nikto tcpdump

# Test network access
ping 10.10.10.10
nc -zv 10.10.10.10 80
nmap -sV 10.10.10.10
```

### Verify Blue Team VM

```bash
curl -i http://10.10.10.30:3000/

ssh debian@10.10.10.30
sudo systemctl status ntopng
sudo systemctl status redis-server
```

## Performance Considerations

### Resource Usage

**Docker-based:**
- 1 VM total
- Shared kernel
- Minimal overhead

**VM-based:**
- 4 VMs total (3 hosts + 1 router)
- Individual kernels
- More realistic but more resources

### Provisioning Time

**Docker-based:**
- ~5-10 minutes (building images)
- Parallel container builds

**VM-based:**
- ~10-15 minutes (installing packages)
- Sequential VM provisioning

## Rollback Procedure

If you need to return to Docker-based architecture:

```bash
# Checkout original commit before migration
git log --oneline | grep "Convert"
git revert <commit-hash>

# Or restore from backup
git checkout <pre-migration-branch>
```

## Future Enhancements

Possible improvements to the VM-based architecture:

1. **Add Monitoring VM** - Dedicated VM for security monitoring
2. **Separate MQTT Broker** - Move Mosquitto to its own VM
3. **Multiple Attackers** - Simulate red/purple team scenarios
4. **Victim Network** - Separate network for victim devices
5. **Firewall VM** - Add pfSense/OPNsense for traffic filtering

## Support

For issues related to the migration:

1. Check [VM_ARCHITECTURE.md](VM_ARCHITECTURE.md) for architecture details
2. Review Ansible role logs during provisioning
3. Verify network connectivity between VMs
4. Check systemd service status on each VM

## Conclusion

The migration from Docker to VM-based architecture provides:
- ✅ More realistic network segmentation
- ✅ Better educational value
- ✅ Easier traffic monitoring
- ✅ Independent VM management
- ✅ True multi-host scenarios

While requiring more resources, the VM-based approach better represents production infrastructure and provides a more authentic penetration testing experience.
