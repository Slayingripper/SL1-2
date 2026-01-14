# Smart Home PV Challenge - CyberRangeCZ Training

This repository contains the Training Definition and Sandbox Definition for the Smart Home PV Challenge, adapted for the CyberRangeCZ Platform.

## Structure

- `training.json`: Defines the training levels, flags, and content.
- `topology.yml`: Defines the sandbox topology (one game server).
- `provisioning/playbook.yml`: Ansible playbook to install Docker and deploy the challenge.
- `provisioning/files/smart-home-pv/`: The challenge source code and Docker Compose configuration.
- `variables.yml`: APG variables.

## Deployment

1. Push this repository to your CyberRangeCZ Git instance.
2. Create a new **Training Definition** in the platform using this repository.
3. Create a **Sandbox Definition** (if needed separately, or the platform might use the same repo for both if configured).
4. Create a Training Instance and run it.

## Access

The challenge runs on the `game-server` VM.
The environment is containerized using Docker Compose.

### Attacker Machine
To access the attacker machine (Kali Linux container), SSH into the `game-server` on port **2224**.

```bash
ssh -p 2224 test@<game-server-ip>
```
Password: `password`

### PV Controller Dashboard
The dashboard is available at `http://<game-server-ip>:8081`.

### Other Services
- Mosquitto MQTT: Port 9001 (WebSocket)
- Modbus TCP: Port 15002
