# Smart Home PV Challenge - CyberRangeCZ

This repository contains the Sandbox Definition for the Smart Home PV Challenge, adapted for the CyberRangeCZ Platform.

## Structure

- `topology.yml`: Defines the sandbox topology (one game server).
- `provisioning/playbook.yml`: Ansible playbook to install Docker and deploy the challenge.
- `provisioning/files/smart-home-pv/`: The challenge source code and Docker Compose configuration.

## Deployment

1. Push this repository to your CyberRangeCZ Git instance.
2. Create a new Sandbox Definition in the platform using this repository.
3. Create a Pool and allocate sandboxes.

## Access

The challenge runs on the `game-server` VM.
The environment is containerized using Docker Compose.

### Attacker Machine
To access the attacker machine (Kali Linux container), SSH into the `game-server` on port **2224**.

```bash
ssh -p 2224 attacker@<game-server-ip>
```
Password: `attacker`

### PV Controller Dashboard
The dashboard is available at `http://<game-server-ip>:8081`.

### Other Services
- Mosquitto MQTT: Port 9001 (WebSocket)
- Modbus TCP: Port 15002
