# Deploying the Cyber Range Version

## Overview

This guide explains how to deploy and test the new cyber range version of the smart-home-pv challenge.

## Prerequisites

- Docker and Docker Compose installed
- **Node.js 18+ and npm** (for building React dashboard)
- Access to the stratocyberlab repository
- playground-net network created (should exist from main platform)

## Deployment Steps

### Step 1: Build React Admin Dashboard

The cyber range includes a professional React-based SCADA HMI admin dashboard.

```bash
cd /home/mastros/gitstuff/stratocyberlab/challenges/smart-home-pv

# Run automated build script
./build-admin-dashboard.sh
```

**Manual build (if script fails):**

```bash
cd admin-dashboard

# Install dependencies
npm install

# Build production bundle
npm run build

# Verify build
ls -la dist/
```

Expected output:
```
dist/
├── assets/
│   ├── index-abc123.js
│   ├── index-xyz789.css
│   └── ...
├── index.html
└── vite.svg
```

### Step 2: Update Server Code

The new cyber range server is in `server_cyber_range.py`. To activate it:

```bash
cd /home/mastros/gitstuff/stratocyberlab/challenges/smart-home-pv

# Backup old server
cp server.py server_ctf_mode.py

# Replace with cyber range version
cp server_cyber_range.py server.py
```

**OR** modify `Dockerfile` to use `server_cyber_range.py`:

```dockerfile
# In Dockerfile, change:
CMD ["python3", "server_cyber_range.py"]
```

### Step 2: Update Victim Container

```bash
# Backup old victim
cp tools/victim/victim_runner.js tools/victim/victim_ctf_mode.js

# Replace with cyber range version
cp tools/victim/victim_cyber_range.js tools/victim/victim_runner.js
```

### Step 3: Rebuild Containers

```bash
# Rebuild all images
docker compose build --no-cache

# Or rebuild specific services
docker compose build pv-controller
docker compose build victim  
docker compose build attacker
```

### Step 4: Start Services

```bash
# Stop old containers
docker compose down

# Start new version
docker compose up -d

# Check all containers running
docker compose ps
```

Expected output:
```
NAME                                    STATUS
scl-challenge-smart-home-pv             running
scl-challenge-mosquitto                 running
scl-challenge-smart-home-pv-attacker    running
scl-challenge-smart-home-pv-victim      running
scl-challenge-smart-home-pv-noise       running
...
```

### Step 5: Verify Cyber Range Mode Active

```bash
# Check server logs
docker compose logs pv-controller | head -n 20
```

You should see:
```
============================================================
Smart Home PV Controller - CYBER RANGE MODE
============================================================
✓ NO shortcuts - real attacks required!
✓ ARP monitoring active
✓ MQTT session tokens in traffic only
✓ Phishing infrastructure ready
✓ Admin dashboard requires stolen credentials
============================================================
```

## Testing the Deployment

### Test 1: Verify No CTF Shortcuts

```bash
# Enter attacker container
docker compose exec attacker bash

# Try old CTF endpoints (should fail)
curl http://172.20.0.65/do_arp_spoof
# Expected: 404 Not Found

curl http://172.20.0.65/flag/mqtt
# Expected: 403 Forbidden (prerequisites not met)
```

### Test 2: Verify Tools Available

```bash
# In attacker container
which arpspoof
# Expected: /usr/sbin/arpspoof

which tcpdump
# Expected: /usr/bin/tcpdump

which tshark
# Expected: /usr/bin/tshark

python3 -c "from pymodbus.client import ModbusTcpClient; print('✓ pymodbus available')"
# Expected: ✓ pymodbus available
```

### Test 3: Verify ARP Monitoring

```bash
# In attacker container
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Start ARP spoofing (run for 30 seconds then stop)
arpspoof -i eth0 -t 172.20.0.72 -r 172.20.0.66 &
sleep 30
kill %1

# Check server detected it
curl http://172.20.0.65/api/challenge/status | jq .
```

Expected response should include:
```json
{
  "events_completed": {
    "arp_spoof_detected": true
  },
  "arp_changes_detected": 1,
  ...
}
```

### Test 4: Verify React Admin Dashboard

```bash
# Check if dashboard was built
ls -la admin-dashboard/dist/index.html

# Access dashboard (from outside attacker container)
curl http://172.20.0.65/admin

# You should get the React index.html
```

**Test login flow:**
1. Open browser: `http://172.20.0.65/admin`
2. Should see industrial-themed login screen
3. Try wrong credentials - should get error
4. Use stolen credentials: `admin:PV-Sec-2024!Admin`
5. Should redirect to professional SCADA dashboard
6. Navigate to "Diagnostics" tab
7. Should see **FLAG #4** displayed prominently

**Test MQTT real-time data:**
1. In dashboard, go to "System Overview"
2. Metrics should update in real-time
3. Power output value should change as telemetry arrives
4. Check browser console - should show MQTT WebSocket connection

### Test 5: Verify Victim Simulation

```bash
# Send test phishing email
curl -X POST http://172.20.0.65/api/send_phishing_email \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Security Alert - Verify Account",
    "link": "http://172.20.0.70:8000/test.html"
  }'

# Watch victim logs
docker compose logs -f victim
```

You should see victim checking email, evaluating suspicion, deciding whether to click.

### Test 5: Verify Modbus Protocol

```bash
# In attacker container
# Test Modbus connection
python3 << 'EOF'
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('172.20.0.65', port=502)
connected = client.connect()
print(f"Modbus connection: {'✓ Success' if connected else '✗ Failed'}")

if connected:
    result = client.read_coils(0, 10)
    if hasattr(result, 'bits'):
        print(f"Read coils: {result.bits[:10]}")
    client.close()
EOF
```

Expected output:
```
Modbus connection: ✓ Success
Read coils: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

## Troubleshooting

### Issue: ARP spoofing not detected

**Symptoms**: `arp_spoof_detected` remains false

**Solution**:
```bash
# Check ARP monitor is running in PV controller
docker compose logs pv-controller | grep -i arp

# Verify attacker has NET_RAW capability
docker inspect scl-challenge-smart-home-pv-attacker | jq '.[].HostConfig.CapAdd'
# Should include: ["NET_RAW", "NET_ADMIN"]

# Ensure IP forwarding enabled
docker compose exec attacker cat /proc/sys/net/ipv4/ip_forward
# Should be: 1
```

### Issue: Victim not clicking phishing links

**Symptoms**: Victim logs show emails ignored

**Solution**:
```bash
# Check victim suspicion calculation
docker compose logs victim | grep suspicion

# Make email more convincing:
curl -X POST http://172.20.0.65/api/send_phishing_email \
  -d '{
    "subject": "URGENT: Security Alert",
    "body": "Your account will be locked if you dont verify immediately",
    "link": "http://172.20.0.65/admin"
  }'
# Using 172.20.0.65 (legitimate domain) reduces suspicion
```

### Issue: Modbus connection refused

**Symptoms**: `Connection refused` on port 502

**Solution**:
```bash
# Check Modbus server started
docker compose logs pv-controller | grep -i modbus

# Check port is open
docker compose exec attacker nmap -p 502 172.20.0.65

# Verify pymodbus installed
docker compose exec pv-controller python3 -c "import pymodbus; print(pymodbus.__version__)"
```

### Issue: Flags not appearing

**Symptoms**: Flag endpoints return 403

**Solution**:
```bash
# Check prerequisite events
curl http://172.20.0.65/api/challenge/status

# Each flag has prerequisites:
# - arp_mitm: requires arp_spoof_detected + packets_captured
# - phishing: requires credentials_stolen
# - admin_access: requires admin_authenticated
# - modbus_attack: requires modbus_write_executed

# Complete prerequisites in order
```

## Rollback to CTF Mode

If you need to revert to the old CTF version:

```bash
cd /home/mastros/gitstuff/stratocyberlab/challenges/smart-home-pv

# Restore old server
cp server_ctf_mode.py server.py

# Restore old victim
cp tools/victim/victim_ctf_mode.js tools/victim/victim_runner.js

# Rebuild
docker compose build
docker compose up -d
```

## Performance Considerations

### Resource Usage

- **CPU**: Victim container uses Puppeteer (Chromium) - ~500MB RAM
- **Network**: ARP monitoring checks every 10 seconds (minimal overhead)
- **Storage**: Packet captures can grow large (use `/tmp` or volume mounts)

### Optimization

```yaml
# In docker-compose.yml, limit victim resources
victim:
  deploy:
    resources:
      limits:
        memory: 1G
        cpus: '0.5'
```

### Cleanup

```bash
# Remove old packet captures
docker compose exec attacker rm -f /tmp/*.pcap

# Clear logs
docker compose exec pv-controller sh -c "rm -f /opt/pv-controller/logs/*.log"

# Restart to reset state
docker compose restart pv-controller victim
```

## Production Deployment

### For Classroom Use

```bash
# 1. Clone repository
git clone <repo-url>
cd challenges/smart-home-pv

# 2. Review configuration
cat docker-compose.yml

# 3. Start services
docker compose up -d

# 4. Distribute walkthrough to students
# - CYBER_RANGE_WALKTHROUGH.md
# - Grading rubric
# - Submission instructions

# 5. Monitor progress
docker compose logs -f pv-controller | grep -E "FLAG|EVENT|CRITICAL"
```

### For Self-Paced Learning

Students can run locally:

```bash
# Ensure playground-net exists
docker network create --subnet=172.20.0.0/24 playground-net

# Start challenge
docker compose up -d

# Follow walkthrough
open CYBER_RANGE_WALKTHROUGH.md
```

## Next Steps

1. ✅ Test complete attack chain
2. ⬜ Create grading automation scripts
3. ⬜ Build React admin dashboard (optional)
4. ⬜ Add metrics collection (attack duration, attempts, success rate)
5. ⬜ Create instructor dashboard showing student progress

## Support

For issues or questions:
1. Check logs: `docker compose logs <service>`
2. Review [CYBER_RANGE_DESIGN.md](CYBER_RANGE_DESIGN.md)
3. Consult [CYBER_RANGE_MIGRATION.md](CYBER_RANGE_MIGRATION.md)
4. File GitHub issue with:
   - Docker version
   - docker compose logs output
   - Steps to reproduce
