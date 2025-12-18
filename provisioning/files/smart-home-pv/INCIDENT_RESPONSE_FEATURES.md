# Incident Response Features

## Overview

The Security Alerts dashboard now includes comprehensive incident response capabilities for blue team operations.

## New Features

### 1. **Export Security Log** 📥

**Purpose**: Export all security events as CSV for forensic analysis, compliance reporting, and incident documentation.

**How to use**:
1. Navigate to Security Alerts tab
2. Click "📥 Export Security Log" button
3. CSV file downloads automatically with timestamp

**CSV Format**:
```csv
Timestamp,Severity,Category,Title,Details,Source
2025-11-21T12:00:00,critical,Data Integrity,Impossible power reading,Power: 150 kW exceeds limits,MQTT Monitor
```

**Use cases**:
- Compliance reporting (NERC-CIP, IEC 62443)
- Incident timeline reconstruction
- Forensic analysis with SIEM tools
- Legal documentation

### 2. **Clear All Alerts** 🧹

**Purpose**: Reset the security dashboard after incident remediation.

**How to use**:
1. Click "🧹 Clear All Alerts" button
2. Confirm the action
3. All security events cleared from memory

**Best practices**:
- Export logs before clearing
- Document remediation actions
- Only clear after incident is fully resolved

### 3. **Acknowledge Alerts** ✅

**Purpose**: Track which alerts have been investigated and by whom.

**How to use**:
1. Click "✅ Acknowledge" on any alert
2. Add investigation notes in modal dialog
3. Submit acknowledgement

**Information tracked**:
- Analyst username (from auth token)
- Acknowledgement timestamp
- Investigation notes and remediation actions

**Example notes**:
```
Investigated MQTT telemetry spike at 12:05 UTC.
Root cause: Attacker fuzzed power_kw field with value 250000.
Remediation: Blocked attacker IP, reset MQTT credentials, 
implemented input validation on telemetry endpoint.
Status: Resolved. No system impact detected.
```

### 4. **Incident Response Guide** 📘

**Purpose**: Quick access to blue team procedures.

**How to use**:
- Click "📘 Incident Response Guide" button
- Opens BLUE_TEAM_GUIDE.md with detection procedures

## API Endpoints

### Export Security Log
```bash
GET /api/admin/security/events/export
Headers: Authorization: Bearer <token>
Response: CSV file download
```

### Clear All Events
```bash
POST /api/admin/security/events/clear
Headers: Authorization: Bearer <token>
Response: {"success": true, "cleared": 15, "message": "Cleared 15 security events"}
```

### Acknowledge Alert
```bash
POST /api/admin/security/acknowledge
Headers: Authorization: Bearer <token>
Body: {
  "timestamp": "2025-11-21T12:00:00.123456",
  "notes": "Investigated and remediated"
}
Response: {"success": true, "event": {...}}
```

## Fixed Issues

### ✅ Modbus False Positives

**Issue**: Unauthorized Modbus write alerts appearing on container restart even without attacks.

**Root cause**: Security event created on every coil state change, including when coil persists across restarts.

**Fix**: 
- Added `last_modbus_alert_time` tracking
- Only create alert if coil changed within last 5 seconds
- Removed duplicate alert from write callback
- Prevents false positives while maintaining real attack detection

**Technical details**:
```python
# Only alert if this is a new attack (within last 5 seconds)
now = datetime.now()
if last_modbus_alert_time is None or (now - last_modbus_alert_time).total_seconds() > 5:
    state.add_security_event(...)
    last_modbus_alert_time = now
```

### ✅ Background Noise False Positives

**Issue**: Malformed data alerts triggered by legitimate background telemetry.

**Root cause**: Noise generator publishes `{"ts": ..., "value": ...}` format, not PV telemetry format.

**Fix**:
```python
# Only analyze if this is a proper PV telemetry message
if 'power_kw' not in payload:
    return  # Ignore background noise telemetry
```

## Blue Team Workflow

### Complete Incident Response Process

1. **Detection**
   - Monitor Security Alerts dashboard
   - Review anomaly indicators (real-time)
   - Check alert severity and category

2. **Investigation**
   - Review alert details and source
   - Correlate multiple alerts
   - Check Power Analytics for patterns
   - Review Diagnostics logs

3. **Documentation**
   - Acknowledge alert with notes
   - Export security log for records
   - Document remediation actions

4. **Remediation**
   - Isolate affected systems
   - Reset compromised credentials
   - Apply security patches
   - Update firewall rules

5. **Recovery**
   - Verify system integrity
   - Clear acknowledged alerts
   - Resume normal operations
   - Update security procedures

## Learning Objectives

Students learn to:
- ✅ Detect ICS/SCADA attacks in real-time
- ✅ Perform security event correlation
- ✅ Document incident response actions
- ✅ Export forensic data for analysis
- ✅ Follow proper incident handling procedures
- ✅ Distinguish false positives from real attacks

## Security Considerations

**Authentication**: All incident response endpoints require valid JWT token.

**Authorization**: Only authenticated admin users can:
- Export security logs
- Clear security events
- Acknowledge alerts

**Audit Trail**: All actions logged with:
- Username
- Timestamp
- Action performed
- Notes/details

## References

- **NIST SP 800-61**: Computer Security Incident Handling Guide
- **SANS Incident Handler's Handbook**: https://www.sans.org/reading-room/
- **MITRE ATT&CK for ICS**: https://attack.mitre.org/matrices/ics/
- **IEC 62443**: Industrial Automation Security Standards
