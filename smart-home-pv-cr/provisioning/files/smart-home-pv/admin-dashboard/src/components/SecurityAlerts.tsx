import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './SecurityAlerts.css';

interface SecurityAlertsProps {
  token: string;
  telemetryData: any[];
}

interface Alert {
  id: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  message: string;
  details?: string;
  source?: string;
  ip?: string;
}

interface AnomalyDetection {
  powerSpike: boolean;
  negativePower: boolean;
  zeroPower: boolean;
  malformedData: boolean;
  suspiciousLogin: boolean;
  multipleFailedLogins: boolean;
  unusualTraffic: boolean;
}

const SecurityAlerts: React.FC<SecurityAlertsProps> = ({ token, telemetryData }) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyDetection>({
    powerSpike: false,
    negativePower: false,
    zeroPower: false,
    malformedData: false,
    suspiciousLogin: false,
    multipleFailedLogins: false,
    unusualTraffic: false
  });
  // Show recent only default is false so persisted alerts are visible after refresh
  const [showRecentOnly, setShowRecentOnly] = useState(false);
  const [securityEvents, setSecurityEvents] = useState<any[]>([]);
    const [blockedIps, setBlockedIps] = useState<Record<string, any>>({});
  const [selectedEvent, setSelectedEvent] = useState<any>(null);
  const [showAcknowledgeModal, setShowAcknowledgeModal] = useState(false);
  const [acknowledgeNotes, setAcknowledgeNotes] = useState('');

  // Detect anomalies in telemetry data
  useEffect(() => {
    if (telemetryData.length === 0) return;

    const latest = telemetryData[telemetryData.length - 1];
    const newAnomalies = { ...anomalies };
    const newAlerts: Alert[] = [];


  
    // Detect power spike (impossible for residential PV)
    if (latest.power_kw && latest.power_kw > 100) {
      newAnomalies.powerSpike = true;
      newAlerts.push({
        id: `spike-${Date.now()}`,
        timestamp: new Date().toISOString(),
        severity: 'critical',
        category: 'Data Integrity',
        message: 'CRITICAL: Impossible power reading detected',
        details: `Power reading of ${latest.power_kw} kW exceeds physical limits of residential PV system (max ~10 kW). Possible data injection attack.`,
        source: 'MQTT Telemetry Monitor'
      });
    }

    // Detect negative power (unusual unless grid export)
    if (latest.power_kw && latest.power_kw < -10) {
      newAnomalies.negativePower = true;
      newAlerts.push({
        id: `negative-${Date.now()}`,
        timestamp: new Date().toISOString(),
        severity: 'high',
        category: 'Anomaly Detection',
        message: 'WARNING: Negative power reading detected',
        details: `Power reading of ${latest.power_kw} kW indicates potential grid attack or sensor manipulation.`,
        source: 'MQTT Telemetry Monitor'
      });
    }

    // Detect all zeros (system offline or attack)
    if (latest.power_kw === 0 && latest.voltage_v === 0 && latest.current_a === 0) {
      newAnomalies.zeroPower = true;
      newAlerts.push({
        id: `zero-${Date.now()}`,
        timestamp: new Date().toISOString(),
        severity: 'high',
        category: 'System Health',
        message: 'WARNING: All telemetry readings at zero',
        details: 'All sensor values are zero. This may indicate a system shutdown, sensor failure, or DoS attack.',
        source: 'MQTT Telemetry Monitor'
      });
    }

    // Detect malformed data - only if power_kw field is present (ignore background noise)
    if (Object.prototype.hasOwnProperty.call(latest, 'power_kw') && (typeof latest.power_kw === 'string' || latest.power_kw === null || isNaN(latest.power_kw))) {
      newAnomalies.malformedData = true;
      newAlerts.push({
        id: `malformed-${Date.now()}`,
        timestamp: new Date().toISOString(),
        severity: 'critical',
        category: 'Data Integrity',
        message: 'CRITICAL: Malformed telemetry data detected',
        details: `Invalid power_kw data: ${JSON.stringify({ power_kw: latest.power_kw })}. Possible type confusion attack or protocol violation.`,
        source: 'MQTT Telemetry Monitor'
      });
    }

    setAnomalies(newAnomalies);
    if (newAlerts.length > 0) {
      setAlerts(prev => [...newAlerts, ...prev].slice(0, 50)); // Keep last 50 alerts
    }
  }, [telemetryData]);

  // Fetch security events from server
  useEffect(() => {
    const fetchSecurityEvents = async () => {
      try {
        const response = await axios.get('/api/admin/security/events', {
          headers: { Authorization: `Bearer ${token}` }
        });
        
        if (response.data.events) {
          setSecurityEvents(response.data.events);
          
          // Generate alerts from security events (suspicious OR high/critical severity)
          const eventAlerts: Alert[] = response.data.events
            .filter((event: any) => event.suspicious || event.severity === 'critical' || event.severity === 'high')
            .map((event: any) => ({
              id: `event-${event.timestamp}`,
              timestamp: event.timestamp,
              severity: event.severity || 'medium',
              category: event.category || 'Security Event',
              message: event.message,
              details: event.details,
              source: event.source || 'Security Monitor',
              ip: event.ip
            }));
          
          if (eventAlerts.length > 0) {
            // Merge with existing alerts, avoiding duplicates by ID
            setAlerts(prev => {
              const existingIds = new Set(prev.map(a => a.id));
              const newAlerts = eventAlerts.filter(a => !existingIds.has(a.id));
              return [...newAlerts, ...prev].slice(0, 100); // Keep last 100 alerts
            });
          }
        }
      } catch (error) {
        console.error('Failed to fetch security events:', error);
      }
    };

    fetchSecurityEvents();
    const interval = setInterval(fetchSecurityEvents, 3000); // Poll every 3 seconds
    return () => clearInterval(interval);
  }, [token]);

  // Fetch blocked IP list
  useEffect(() => {
    const fetchBlocked = async () => {
      try {
        const resp = await axios.get('/api/admin/security/blocked', { headers: { Authorization: `Bearer ${token}` } });
        setBlockedIps(resp.data.blocked_ips || {});
      } catch (err) {
        // ignore
      }
    };
    fetchBlocked();
    const bi = setInterval(fetchBlocked, 10000);
    return () => clearInterval(bi);
  }, [token]);

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return '🔴';
      case 'high': return '🟠';
      case 'medium': return '🟡';
      case 'low': return '🟢';
      default: return '⚪';
    }
  };

  const getSeverityClass = (severity: string) => {
    return `alert-${severity}`;
  };

  const acknowledgeAlert = (alertId: string) => {
    setAlerts(prev => prev.filter(alert => alert.id !== alertId));
  };

  const clearAllAlerts = async () => {
    if (!confirm('Are you sure you want to clear all security alerts? This action cannot be undone.')) {
      return;
    }
    
    try {
      await axios.post('/api/admin/security/events/clear', {}, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setAlerts([]);
      setSecurityEvents([]);
      alert('✅ All security events cleared successfully');
    } catch (error) {
      console.error('Failed to clear alerts:', error);
      alert('❌ Failed to clear alerts. Please try again.');
    }
  };

  const clearLocalAlerts = () => {
    setAlerts([]);
  };

  const exportSecurityLog = async () => {
    try {
      const response = await axios.get('/api/admin/security/events/export', {
        headers: { 'Authorization': `Bearer ${token}` },
        responseType: 'blob'
      });
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `security_events_${new Date().toISOString().split('T')[0]}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
      alert('✅ Security log exported successfully');
    } catch (error) {
      console.error('Failed to export security log:', error);
      alert('❌ Failed to export security log. Please try again.');
    }
  };

  const exportFailedLogins = async () => {
    try {
      const response = await axios.get('/api/admin/security/failed_logins/export', {
        headers: { 'Authorization': `Bearer ${token}` },
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `failed_logins_${new Date().toISOString().split('T')[0]}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      alert('✅ Failed login export initiated');
    } catch (error) {
      console.error('Failed to export failed logins:', error);
      alert('❌ Failed to export failed logins.');
    }
  };

  const exportAnomalies = async () => {
    try {
      const response = await axios.get('/api/admin/security/anomalies/export', {
        headers: { 'Authorization': `Bearer ${token}` },
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `anomalies_${new Date().toISOString().split('T')[0]}.json`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      alert('✅ Anomalies export initiated');
    } catch (error) {
      console.error('Failed to export anomalies:', error);
      alert('❌ Failed to export anomalies.');
    }
  };

  const acknowledgeEvent = async (event: any) => {
    setSelectedEvent(event);
    setShowAcknowledgeModal(true);
  };

  const submitAcknowledgement = async () => {
    if (!selectedEvent) return;
    
    try {
      let serverTimestamp = selectedEvent.timestamp;
      // If this is a client/local event (no server event), create it first
      if (!selectedEvent.id?.startsWith('event-')) {
        const createResp = await axios.post('/api/admin/security/events/create', {
          timestamp: selectedEvent.timestamp,
          severity: selectedEvent.severity,
          category: selectedEvent.category,
          title: selectedEvent.message,
          details: selectedEvent.details,
          source: selectedEvent.source,
          suspicious: true
        }, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        serverTimestamp = createResp.data.event.timestamp;
      }

      // Now acknowledge the server-side event
      await axios.post('/api/admin/security/acknowledge', {
        timestamp: serverTimestamp,
        notes: acknowledgeNotes
      }, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      setShowAcknowledgeModal(false);
      setAcknowledgeNotes('');
      setSelectedEvent(null);
      alert('✅ Alert acknowledged successfully');
    } catch (error) {
      console.error('Failed to acknowledge alert:', error);
      alert('❌ Failed to acknowledge alert. Please try again.');
    }
  };

  // Block an IP and revoke tokens
  const blockIp = async (ip: string) => {
    if (!ip) return;
    if (!confirm(`Block and disconnect IP ${ip}? This will revoke any active admin sessions from that IP.`)) return;
    try {
      const resp = await axios.post('/api/admin/security/block', { ip, reason: 'Manual block via Dashboard' }, { headers: { Authorization: `Bearer ${token}` } });
      alert('✅ IP blocked: ' + ip + ` (revoked: ${resp.data.revoked_sessions})`);
      // Refresh blocked ip list
      const bl = await axios.get('/api/admin/security/blocked', { headers: { Authorization: `Bearer ${token}` } });
      setBlockedIps(bl.data.blocked_ips || {});
    } catch (e) {
      console.error('Block failed', e);
      alert('❌ Failed to block IP.');
    }
  };

  const disconnectIp = async (ip: string) => {
    if (!ip) return;
    try {
      const resp = await axios.post('/api/admin/security/disconnect', { ip }, { headers: { Authorization: `Bearer ${token}` } });
      alert('✅ Disconnected IP: ' + ip + ` (revoked: ${resp.data.revoked_sessions})`);
    } catch (e) {
      console.error('Disconnect failed', e);
      alert('❌ Failed to disconnect IP.');
    }
  };

  const unblockIp = async (ip: string) => {
    if (!ip) return;
    if (!confirm(`Unblock IP ${ip}?`)) return;
    try {
      await axios.post('/api/admin/security/unblock', { ip }, { headers: { Authorization: `Bearer ${token}` } });
      // Refresh again
      const bl = await axios.get('/api/admin/security/blocked', { headers: { Authorization: `Bearer ${token}` } });
      setBlockedIps(bl.data.blocked_ips || {});
      alert('✅ Unblocked IP: ' + ip);
    } catch (e) {
      console.error('Unblock failed', e);
      alert('❌ Failed to unblock IP.');
    }
  };

  // const criticalCount = alerts.filter(a => a.severity === 'critical').length;
  // const highCount = alerts.filter(a => a.severity === 'high').length;
  // Filter alerts by recent-only if enabled (last 5 minutes)
  const nowTs = new Date().getTime();
  const recentThresholdMs = 5 * 60 * 1000; // 5 minutes
  const filteredAlerts = showRecentOnly
    ? alerts.filter(a => new Date(a.timestamp).getTime() >= nowTs - recentThresholdMs)
    : alerts;
  const criticalCount = filteredAlerts.filter(a => a.severity === 'critical').length;
  const highCount = filteredAlerts.filter(a => a.severity === 'high').length;

  return (
    <div className="security-alerts-container">
      <div className="alerts-header">
        <h2>🛡️ Security Operations Center</h2>
        <div className="alert-summary">
          <div className="alert-stat critical">
            <span className="stat-value">{criticalCount}</span>
            <span className="stat-label">Critical</span>
          </div>
          <div className="alert-stat high">
            <span className="stat-value">{highCount}</span>
            <span className="stat-label">High</span>
          </div>
          <div className="alert-stat total">
            <span className="stat-value">{filteredAlerts.length}</span>
            <span className="stat-label">Total Alerts</span>
          </div>
        </div>
      </div>

      <div className="anomaly-indicators">
        <h3>Real-Time Anomaly Detection</h3>
        <div className="indicator-grid">
          <div className={`indicator ${anomalies.powerSpike ? 'active' : ''}`}>
            <span className="indicator-icon">⚡</span>
            <span className="indicator-label">Power Spike</span>
            {anomalies.powerSpike && <span className="indicator-status">DETECTED</span>}
          </div>
          <div className={`indicator ${anomalies.negativePower ? 'active' : ''}`}>
            <span className="indicator-icon">⬇️</span>
            <span className="indicator-label">Negative Power</span>
            {anomalies.negativePower && <span className="indicator-status">DETECTED</span>}
          </div>
          <div className={`indicator ${anomalies.zeroPower ? 'active' : ''}`}>
            <span className="indicator-icon">🔌</span>
            <span className="indicator-label">Zero Values</span>
            {anomalies.zeroPower && <span className="indicator-status">DETECTED</span>}
          </div>
          <div className={`indicator ${anomalies.malformedData ? 'active' : ''}`}>
            <span className="indicator-icon">⚠️</span>
            <span className="indicator-label">Malformed Data</span>
            {anomalies.malformedData && <span className="indicator-status">DETECTED</span>}
          </div>
        </div>
      </div>

      <div className="alerts-actions">
        <label className="recent-toggle">
          <input type="checkbox" checked={showRecentOnly} onChange={(e) => setShowRecentOnly(e.target.checked)} />
          Show recent only (5m)
        </label>
        <button className="action-btn" onClick={clearLocalAlerts}>
          Clear Local Alerts
        </button>
        <button className="action-btn" onClick={clearAllAlerts}>
          🧹 Clear All Alerts
        </button>
        <button className="action-btn secondary" onClick={exportSecurityLog}>
          📥 Export Security Log
        </button>
        <button className="action-btn secondary" onClick={exportFailedLogins}>
          📥 Export Failed Logins
        </button>
        <button className="action-btn secondary" onClick={exportAnomalies}>
          📥 Export Anomalies
        </button>
        <button className="action-btn secondary" onClick={() => window.open('/BLUE_TEAM_GUIDE.md', '_blank')}>
          📘 Incident Response Guide
        </button>
      </div>

      <div className="alerts-list">
        <h3>Active Security Alerts</h3>
        {alerts.length === 0 ? (
          <div className="no-alerts">
            <span className="no-alerts-icon">✅</span>
            <p>No active security alerts</p>
            <small>System monitoring active - anomalies will be detected automatically</small>
          </div>
        ) : (
          <div className="alerts-scroll">
            {alerts.map(alert => (
              <div key={alert.id} className={`alert-item ${getSeverityClass(alert.severity)}`}>
                <div className="alert-header">
                  <div className="alert-title">
                    <span className="alert-severity-icon">{getSeverityIcon(alert.severity)}</span>
                    <span className="alert-category">{alert.category}</span>
                    <span className="alert-time">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <button className="alert-dismiss" onClick={() => acknowledgeAlert(alert.id)}>
                    ✕
                  </button>
                </div>
                <div className="alert-message">{alert.message}</div>
                {alert.details && (
                  <div className="alert-details">{alert.details}</div>
                )}
                {alert.source && (
                  <div className="alert-source">Source: {alert.source}</div>
                )}
                {alert.ip && (
                  <div className="alert-source">IP: <code>{alert.ip}</code> {blockedIps && blockedIps[alert.ip] && <span style={{marginLeft:'8px', color:'#ff5252', fontWeight:700}}>BLOCKED</span>}</div>
                )}
                <div className="alert-actions">
                  <button 
                    className="btn-acknowledge" 
                    onClick={() => acknowledgeEvent(alert)}
                  >
                    ✅ Acknowledge
                  </button>
                  {alert.ip && (
                    <>
                        <button className="btn-block" onClick={() => blockIp(alert.ip!)}>
                        ⛔ Block & Disconnect
                      </button>
                      <button className="btn-disconnect" onClick={() => disconnectIp(alert.ip!)}>
                        📴 Disconnect
                      </button>
                        <button className="btn-unblock" onClick={() => unblockIp(alert.ip!)}>
                        🔓 Unblock
                      </button>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="blocked-ips">
        <h3>🚫 Blocked IPs</h3>
        {Object.keys(blockedIps).length === 0 ? (
          <p>No IP addresses are currently blocked.</p>
        ) : (
          <ul>
            {Object.entries(blockedIps).map(([ip, meta]) => (
              <li key={ip}>
                <code>{ip}</code> - {meta.reason || 'Blocked by admin'} - <small>{meta.blocked_at}</small>
                <button className="btn-unblock" style={{ marginLeft: '10px' }} onClick={() => unblockIp(ip)}>🔓 Unblock</button>
              </li>
            ))}
          </ul>
        )}
      </div>

      {showAcknowledgeModal && (
        <div className="modal-overlay" onClick={() => setShowAcknowledgeModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Acknowledge Security Alert</h3>
            <div className="modal-body">
              <p><strong>Alert:</strong> {selectedEvent?.title || selectedEvent?.message}</p>
              <p><strong>Severity:</strong> {selectedEvent?.severity}</p>
              <textarea
                placeholder="Add investigation notes and remediation actions taken..."
                value={acknowledgeNotes}
                onChange={(e) => setAcknowledgeNotes(e.target.value)}
                rows={6}
                style={{ width: '100%', marginTop: '10px', padding: '10px' }}
              />
            </div>
            <div className="modal-actions">
              <button className="btn-primary" onClick={submitAcknowledgement}>
                Submit Acknowledgement
              </button>
              <button className="btn-secondary" onClick={() => setShowAcknowledgeModal(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="investigation-tips">
        <h3>🔍 Investigation Guide</h3>
        <div className="tips-content">
          <div className="tip-item">
            <strong>When you see anomalies:</strong>
            <ul>
              <li>Check the Power Analytics view for unusual patterns</li>
              <li>Review Diagnostics for detailed event logs</li>
              <li>Look for correlation between multiple alerts</li>
              <li>Check network traffic for suspicious MQTT messages</li>
            </ul>
          </div>
          <div className="tip-item">
            <strong>Common attack indicators:</strong>
            <ul>
              <li>Impossible sensor values ({'>'}100 kW power)</li>
              <li>Type confusion (strings instead of numbers)</li>
              <li>Sudden zero values across all sensors</li>
              <li>Multiple failed login attempts</li>
              <li>Unexpected Modbus writes</li>
            </ul>
          </div>
          <div className="tip-item">
            <strong>Defensive actions:</strong>
            <ul>
              <li>Isolate affected systems from network</li>
              <li>Review authentication logs for unauthorized access</li>
              <li>Capture network traffic for forensic analysis</li>
              <li>Reset compromised credentials</li>
              <li>Document all findings for incident report</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

  

export default SecurityAlerts;
