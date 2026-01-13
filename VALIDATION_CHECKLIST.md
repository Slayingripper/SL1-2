# Deployment Validation Checklist

Use this checklist to verify successful deployment of the VM-based cyber range.

## Pre-Deployment

- [ ] Repository pushed to CyberRangeCZ Git
- [ ] Training Definition created
- [ ] Sandbox Definition configured
- [ ] Required resources available (4 VMs)

## VM Provisioning

### Router VM
- [ ] VM created and running
- [ ] IP: 10.10.10.1 assigned
- [ ] WAN interface connected (100.100.100.0/24)
- [ ] LAN interface connected (10.10.10.0/24)

### Blue Team VM
- [ ] VM created and running (Debian 12)
- [ ] IP: 10.10.10.10 assigned
- [ ] SSH accessible
- [ ] Application files copied to `/opt/pv-controller/`
- [ ] Python dependencies installed
- [ ] Node.js installed for victim simulator

### Attacker VM
- [ ] VM created and running (Debian 12)
- [ ] IP: 10.10.10.20 assigned
- [ ] User `attacker` created with password `attacker`
- [ ] SSH accessible with password authentication
- [ ] Sudo access configured
- [ ] Pentest tools installed
- [ ] Custom scripts in `/home/attacker/tools/`

### Admin Dashboard VM
- [ ] VM created and running (Ubuntu Noble)
- [ ] IP: 10.10.10.30 assigned
- [ ] SSH accessible
- [ ] Node.js and npm installed
- [ ] React app built successfully
- [ ] Nginx configured and running

## Service Validation

### Blue Team Services

```bash
# SSH to Blue Team VM
ssh debian@10.10.10.10
```

- [ ] PV Controller service running
  ```bash
  systemctl status pv-controller
  # Should show: active (running)
  ```

- [ ] PV Controller API responding
  ```bash
  curl http://localhost/api/health
  # Should return JSON response
  ```

- [ ] Mosquitto MQTT broker running
  ```bash
  systemctl status mosquitto
  # Should show: active (running)
  ```

- [ ] MQTT accepting connections
  ```bash
  mosquitto_sub -h localhost -t '$SYS/#' -C 1
  # Should receive system message
  ```

- [ ] Modbus TCP server listening
  ```bash
  netstat -tlnp | grep 15002
  # Should show Python listening on 15002
  ```

- [ ] Victim simulator running
  ```bash
  systemctl status victim-simulator
  # Should show: active (running)
  ```

- [ ] Log directory exists and writable
  ```bash
  ls -la /opt/pv-controller/logs/
  # Should show log files
  ```

### Attacker Services

```bash
# SSH to Attacker VM
ssh attacker@10.10.10.20
# Password: attacker
```

- [ ] SSH authentication successful
- [ ] Sudo access works
  ```bash
  sudo -l
  # Should list sudo privileges
  ```

- [ ] Tools installed and accessible
  ```bash
  which nmap hydra nikto tcpdump scapy
  # All should return paths
  ```

- [ ] Python packages installed
  ```bash
  python3 -c "import pymodbus, scapy, requests"
  # Should not error
  ```

- [ ] Custom scripts present
  ```bash
  ls -la ~/tools/
  # Should show attacker_modbus.py, demo_attacks.sh, etc.
  ```

### Admin Dashboard Services

```bash
# SSH to Admin Dashboard VM
ssh ubuntu@10.10.10.30
```

- [ ] Nginx service running
  ```bash
  systemctl status nginx
  # Should show: active (running)
  ```

- [ ] Built files exist
  ```bash
  ls -la /opt/admin-dashboard/dist/
  # Should show index.html and assets/
  ```

- [ ] Nginx config valid
  ```bash
  nginx -t
  # Should show: syntax is ok, test is successful
  ```

- [ ] Dashboard accessible locally
  ```bash
  curl http://localhost
  # Should return HTML
  ```

## Network Connectivity

### From Attacker VM

```bash
ssh attacker@10.10.10.20
```

- [ ] Can ping router
  ```bash
  ping -c 3 10.10.10.1
  ```

- [ ] Can ping Blue Team
  ```bash
  ping -c 3 10.10.10.10
  ```

- [ ] Can ping Admin Dashboard
  ```bash
  ping -c 3 10.10.10.30
  ```

- [ ] Can connect to PV Controller
  ```bash
  nc -zv 10.10.10.10 80
  ```

- [ ] Can connect to MQTT
  ```bash
  nc -zv 10.10.10.10 1883
  nc -zv 10.10.10.10 9001
  ```

- [ ] Can connect to Modbus
  ```bash
  nc -zv 10.10.10.10 15002
  ```

### From Blue Team VM

```bash
ssh debian@10.10.10.10
```

- [ ] Can reach internet (for package updates)
  ```bash
  ping -c 3 8.8.8.8
  ```

- [ ] Can reach Admin Dashboard
  ```bash
  ping -c 3 10.10.10.30
  ```

## Functional Testing

### Web Interface

- [ ] PV Controller web accessible
  ```
  http://10.10.10.10
  # Should show PV controller interface
  ```

- [ ] Admin Dashboard accessible
  ```
  http://10.10.10.30
  # Should show React dashboard
  ```

- [ ] Dashboard connects to backend
  ```
  # Check browser console, should see MQTT/API connections
  ```

### MQTT Functionality

From Attacker VM:
```bash
ssh attacker@10.10.10.20
```

- [ ] Can subscribe to topics
  ```bash
  timeout 5 mosquitto_sub -h 10.10.10.10 -t 'pv/#' -v
  # Should see messages or timeout
  ```

- [ ] Can publish messages
  ```bash
  mosquitto_pub -h 10.10.10.10 -t 'pv/test' -m 'test'
  # Should succeed without error
  ```

### Modbus Functionality

From Attacker VM:
```bash
ssh attacker@10.10.10.20
```

- [ ] Can connect to Modbus server
  ```bash
  python3 -c "
  from pymodbus.client import ModbusTcpClient
  c = ModbusTcpClient('10.10.10.10', 15002)
  print('Connected:', c.connect())
  c.close()
  "
  # Should print: Connected: True
  ```

- [ ] Can read holding registers
  ```bash
  python3 ~/tools/attacker_modbus.py --target 10.10.10.10 --port 15002 --action read
  # Should return register values
  ```

### API Functionality

From Attacker VM:
```bash
ssh attacker@10.10.10.20
```

- [ ] Health endpoint responds
  ```bash
  curl http://10.10.10.10/api/health
  # Should return JSON: {"status": "healthy"}
  ```

- [ ] Login endpoint exists
  ```bash
  curl -X POST http://10.10.10.10/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"test"}'
  # Should return response (valid or error)
  ```

## Security Events

### Log Generation

On Blue Team VM:
```bash
ssh debian@10.10.10.10
```

- [ ] Security events logged
  ```bash
  cat /opt/pv-controller/logs/security_events.json
  # Should contain event entries
  ```

- [ ] Failed logins tracked
  ```bash
  cat /opt/pv-controller/logs/failed_logins.json
  # Should be empty or contain attempts
  ```

- [ ] Blocked IPs tracked
  ```bash
  cat /opt/pv-controller/logs/blocked_ips.json
  # Should be empty or contain IPs
  ```

### Traffic Capture

- [ ] PCAP files generated
  ```bash
  ls -la /opt/pv-controller/logs/*.pcap
  # Should show pcap files or be empty initially
  ```

## Attack Scenario Testing

### Test 1: Port Scanning

From Attacker VM:
```bash
ssh attacker@10.10.10.20
nmap -sV -p- 10.10.10.10
```

- [ ] Scan completes successfully
- [ ] Discovers ports: 80, 1883, 9001, 15002
- [ ] Identifies services correctly

### Test 2: MQTT Interception

From Attacker VM:
```bash
ssh attacker@10.10.10.20
mosquitto_sub -h 10.10.10.10 -t 'pv/status' -v
```

- [ ] Receives status messages
- [ ] Messages contain expected data
- [ ] Can observe victim simulator activity

### Test 3: Modbus Attack

From Attacker VM:
```bash
ssh attacker@10.10.10.20
cd ~/tools
./demo_attacks.sh
```

- [ ] Attack script executes
- [ ] Successfully writes to Modbus coils
- [ ] Impact visible on PV controller

### Test 4: Web Exploitation

From Attacker VM:
```bash
ssh attacker@10.10.10.20
nikto -h http://10.10.10.10
```

- [ ] Nikto scan completes
- [ ] Discovers vulnerabilities
- [ ] API endpoints accessible

## Dashboard Monitoring

From web browser:
```
http://10.10.10.30
```

- [ ] Dashboard loads completely
- [ ] Real-time updates working
- [ ] MQTT messages displayed
- [ ] Security events shown
- [ ] Modbus traffic visible
- [ ] Diagnostics panel functional

## Documentation Verification

- [ ] README.md updated with VM architecture
- [ ] VM_ARCHITECTURE.md provides detailed info
- [ ] MIGRATION_GUIDE.md explains conversion
- [ ] QUICK_START.md has user instructions
- [ ] All IP addresses consistent (10.10.10.x)
- [ ] All examples use correct hostnames/IPs

## Training Platform Integration

- [ ] Training levels accessible
- [ ] Flags are correct
- [ ] Hints match new architecture
- [ ] Instructions reference correct IPs/ports
- [ ] Access level passkey works

## Common Issues Resolution

If any checks fail, consult:

1. **Service not running**
   - Check: `journalctl -u <service-name> -n 50`
   - Action: `systemctl restart <service-name>`

2. **Network connectivity issues**
   - Check: `ip addr show`
   - Check: `ip route show`
   - Check: `ping 10.10.10.1`

3. **Dashboard not loading**
   - Check: `/var/log/nginx/error.log`
   - Check: Build exists at `/opt/admin-dashboard/dist/`
   - Action: `systemctl restart nginx`

4. **Python errors**
   - Check: `pip3 list | grep <package>`
   - Action: `pip3 install <package>`

5. **Permissions issues**
   - Check: `ls -la /opt/pv-controller/`
   - Action: `chmod 755 /opt/pv-controller/`

## Final Validation

- [ ] All VMs running and accessible
- [ ] All services active
- [ ] Network connectivity confirmed
- [ ] Attack scenarios functional
- [ ] Monitoring/logging working
- [ ] Documentation accurate
- [ ] Training platform integrated

## Sign-Off

**Deployment Date:** _______________  
**Validated By:** _______________  
**Platform Version:** _______________  
**Issues Found:** _______________  
**Status:** ⬜ Passed / ⬜ Failed

---

**Note:** This checklist should be completed after each deployment to ensure all components are working correctly before students access the cyber range.
