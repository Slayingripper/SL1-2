# Blue Team Defense Guide - Smart Home PV Cyber Range

## Overview

This cyber range provides a complete **red team vs blue team** learning experience. While attackers exploit the PV SCADA system, defenders must detect and respond to the attacks using the built-in Security Operations Center (SOC).

## Blue Team Learning Objectives

### 1. Real-Time Threat Detection
Learn to identify ongoing attacks by monitoring:
- Anomalous sensor data (impossible values, type confusion)
- Suspicious authentication attempts (brute force, phishing)
- Unauthorized protocol operations (Modbus writes, MQTT injections)

### 2. SCADA/ICS Security Monitoring
Understand industrial control system specific threats:
- Protocol abuse (Modbus, MQTT)
- Sensor manipulation and data integrity attacks
- Unauthorized control commands

### 3. Incident Response
Practice defensive actions when attacks are detected:
- System isolation
- Log analysis and forensics
- Credential reset and access control

## Security Alerts Dashboard

Access the **Security Alerts** tab in the admin dashboard to see:

### Real-Time Anomaly Indicators
Visual indicators that light up when attacks are detected:
- ⚡ **Power Spike**: Impossible readings (>100 kW for residential PV)
- ⬇️ **Negative Power**: Unusual grid export or sensor manipulation
- 🔌 **Zero Values**: System offline or DoS attack
- ⚠️ **Malformed Data**: Type confusion or protocol violations

### Active Security Alerts
Categorized and prioritized alerts showing:
- **Severity**: Critical, High, Medium, Low
- **Category**: Data Integrity, Authentication, ICS Protocol, System Health
- **Details**: What happened, why it's suspicious, and what to investigate
- **Source**: Which monitoring system detected the anomaly

### Attack Detection Examples

#### Data Injection Attack
```
🔴 CRITICAL: Impossible power reading detected
Power reading of 999.99 kW exceeds physical limits 
of residential PV system (max ~10 kW). 
Possible data injection attack.
Source: MQTT Telemetry Monitor
```

#### Brute Force Attack
```
🟠 HIGH: Multiple failed login attempts detected
3 failed attempts from 172.20.0.70
User: admin
Source: Authentication Monitor
```

#### Modbus Exploitation
```
🔴 CRITICAL: Unauthorized Modbus write operation
Coil 1 was set to TRUE, triggering system HALT.
This indicates direct ICS protocol exploitation.
Source: Modbus Monitor
```

## How to Defend (Blue Team Actions)

### 1. Monitor the Dashboard
- Keep the **Security Alerts** tab open during red team exercises
- Watch for anomaly indicators lighting up
- Review alert messages as they appear in real-time

### 2. Investigate Suspicious Activity
When you see anomalies:
- **Check Power Analytics**: Look for unusual telemetry patterns
- **Review Diagnostics**: Examine detailed event logs
- **Correlate Alerts**: Multiple alerts may indicate coordinated attack
- **Network Analysis**: Suspicious MQTT/Modbus traffic patterns

### 3. Common Attack Patterns to Recognize

#### Phase 1: Reconnaissance
- **Alert**: Multiple rapid connections to different ports
- **Action**: Monitor network scan detection in logs

#### Phase 2: Man-in-the-Middle
- **Alert**: Failed login attempts followed by successful login
- **Action**: Check authentication logs for unusual patterns

#### Phase 3: Data Manipulation
- **Alert**: Power spike, negative values, or zero readings
- **Action**: Verify MQTT message integrity, check for injected data

#### Phase 4: System Control
- **Alert**: Unauthorized Modbus write operations
- **Action**: Review ICS protocol logs, check coil/register changes

### 4. Defensive Response Actions

When attacks are detected:

1. **Immediate Actions**
   - Document the alert (screenshot, copy details)
   - Note the timestamp and affected systems
   - Check if system is still operational

2. **Investigation**
   - Use Diagnostics tab to review full event timeline
   - Check Power Analytics for data integrity issues
   - Look for patterns across multiple alert types

3. **Containment**
   - In a real scenario: Isolate affected systems
   - Reset compromised credentials
   - Block suspicious IP addresses
   - Disable vulnerable protocols temporarily

4. **Recovery**
   - Verify system integrity after attack
   - Restore from known-good state if needed
   - Update security controls based on lessons learned

## Blue Team Challenge Objectives

### Detection Success Criteria
Can you detect all 6 attack phases?

- [ ] **Phase 1 Detection**: Network reconnaissance (port scanning)
- [ ] **Phase 2 Detection**: Brute force authentication attempts
- [ ] **Phase 3 Detection**: MQTT data injection (impossible values)
- [ ] **Phase 4 Detection**: MQTT data injection (negative/zero values)
- [ ] **Phase 5 Detection**: MQTT data injection (malformed data)
- [ ] **Phase 6 Detection**: Modbus exploitation (unauthorized writes)

### Response Time Goals
- Alert acknowledgment: < 30 seconds
- Initial investigation: < 2 minutes
- Incident documentation: < 5 minutes

## Investigation Tips

### Look for These Indicators

**Authentication Anomalies**:
- Multiple failed logins followed by success = Brute force attack
- Login from unusual IP address = Credential theft
- Login outside normal hours = Compromised account

**Data Anomalies**:
- Values exceeding physical limits = Sensor manipulation
- Type confusion (strings instead of numbers) = Protocol attack
- All zeros across sensors = DoS attack
- Sudden spikes or drops = Data injection

**Protocol Anomalies**:
- Unexpected Modbus writes = Direct ICS exploitation
- Invalid MQTT session tokens = Session hijacking attempt
- Malformed protocol messages = Fuzzing/DoS

### Correlation Patterns

Multiple alerts in sequence may indicate:
1. **Recon → Brute Force → Data Injection** = Persistent attacker
2. **Failed Auth → MQTT Anomaly** = Stolen credentials used for injection
3. **Data Anomaly → Modbus Write** = Escalation to ICS control

## Learning Outcomes

After completing blue team exercises, you should be able to:

✅ Recognize common ICS/SCADA attack patterns
✅ Use real-time monitoring to detect anomalies
✅ Correlate multiple security events to identify attack chains
✅ Document incidents with timestamps, details, and impact
✅ Recommend defensive controls based on observed attacks
✅ Understand the difference between IT and OT security monitoring

## Advanced Blue Team Exercises

### Exercise 1: Timeline Reconstruction
1. Run the complete attack demo
2. Use Security Alerts to build a timeline of events
3. Document: What happened, when, and in what order?

### Exercise 2: Attack Attribution
1. Analyze multiple alerts during an attack
2. Determine: Which attacks came from the same source?
3. Identify: What was the attacker's goal?

### Exercise 3: Defense Planning
1. Review all detected anomalies
2. Propose: What controls could prevent each attack?
3. Prioritize: Which defenses provide the most value?

### Exercise 4: Incident Report
After an attack, create a formal incident report including:
- Executive summary
- Timeline of events
- Attack vectors used
- Systems affected
- Recommended remediation
- Lessons learned

## Real-World Applicability

These detection techniques apply to real industrial environments:
- **Energy Management Systems**: Solar, wind, battery storage
- **Building Automation**: HVAC, lighting, access control
- **Manufacturing**: PLCs, SCADA, industrial networks
- **Critical Infrastructure**: Power grid, water treatment, oil & gas

The same anomaly detection principles work across different protocols:
- Modbus (this lab)
- DNP3 (electric utilities)
- BACnet (building automation)
- OPC UA (industrial automation)

---

**Remember**: The best defense is detection. You can't prevent what you can't see!

## Troubleshooting: Frequent 'Malformed telemetry data' Alerts

If you're seeing repeated `CRITICAL: Malformed telemetry data detected` alerts while no red team attack is running, this typically means background telemetry messages do not match the PV telemetry schema (i.e. they use different fields such as `value` instead of `power_kw`). Follow these steps to diagnose and resolve:

1. Confirm MQTT telemetry format
   - Subscribe to telemetry and observe a few messages:
   ```bash
   # Subscribe to 10 messages
   mosquitto_sub -h 172.20.0.66 -t 'pv/telemetry' -C 10 -v
   ```
   - Look for the presence of `power_kw` in the payload. Example (correct): `{\"power_kw\":123.4,\"voltage_v\":230,...}`; example (noise): `{\"ts\":...,\"value\":42}`.

2. Check server logs for detection details
   ```bash
   docker compose logs pv-controller --tail 200 | grep -i "malformed" -n
   docker compose logs pv-controller --tail 200 | grep -i "MQTT Telemetry Monitor" -n
   ```
   - The logs will show the server event details and timestamps; note whether the payload contains `power_kw` or other keys.

3. Determine the noise source
   - The challenge includes a `noise` generator and a `telemetry-seeder` that publish non-PV telemetry. They are expected to use a `value`/`ts` schema.
   - If you want to disable noise for focused blue team training, stop the `noise` container:
   ```bash
   docker compose stop noise
   ```
   - Resume it later with `docker compose start noise`.

4. Verify client-side detection
   - The Security Alerts UI flags malformed messages if `power_kw` is present but not a numeric value. If the UI shows malformed payloads like `{\"ts\":...,\"value\":13}`, the UI logic may need to ignore messages without `power_kw`.
   - We have implemented server-side and client-side checks to only analyze messages with `power_kw` to avoid false positives. If you're still seeing alerts, rebuild the dashboard after pulling the latest changes.

5. Adjust detection sensitivity (advanced)
   - Location: `server_cyber_range.py` (server checks `power_kw`) and `admin-dashboard/src/components/SecurityAlerts.tsx` (client detection for `power_kw`).
   - Use these options to fine-tune detection: raise power thresholds, ignore undefined values, or throttle duplicate alerts via `last_modbus_alert_time` logic.

6. If you're actively running the demo attack and still get false positives outside the expected phases, confirm the demo phases are running in the `attacker` container and only one attack sequence is running at a time.

## Quick Mitigation Checklist for Trainers
- Disable `noise` container (if you want only student attacks to trigger alerts):
  ```bash
  docker compose stop noise
  ```
- Rebuild and restart dashboard if you changed UI logic:
  ```bash
  docker compose build pv-controller && docker compose up -d pv-controller
  ```
- Export security logs before clearing alerts for record keeping:
  ```bash
  curl -H "Authorization: Bearer <token>" http://172.20.0.65/api/admin/security/events/export -o security_events.csv
  ```
