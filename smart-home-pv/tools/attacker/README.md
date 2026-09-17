# Attacker container

This container contains common pentesting tools targeted for this challenge: nmap, arp-scan, tcpdump, mosquitto-clients, sqlmap, hping3, and Python with `pymodbus` and `paho-mqtt` installed.

Usage:

```
# Start an interactive attacker shell
docker compose -f challenges/smart-home-pv/docker-compose.yml run --service-ports attacker bash

# Example: Use the included Python modbus client
python3 /home/attacker/tools/attacker_modbus.py 172.20.0.65 15002

# Example: Subscribe to pv/status to capture session token
mosquitto_sub -h 172.20.0.66 -t pv/status -C 1

# Example SQLi test
sqlmap -u "http://172.20.0.65/api/admin/login" --data "username=admin&password=admin" --batch
```

If you prefer to use other tools (bettercap, burpsuite, etc.), install them inside the container or mount them as needed.
