import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './SecurityAlerts.css';
import { logAdminActivity } from '../utils/activityLogger';

interface SecurityAlertsProps {
  token: string;
  telemetryData: any[];
  systemStatus?: any;
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

const SecurityAlerts: React.FC<SecurityAlertsProps> = ({ token, telemetryData, systemStatus }) => {
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
  const [sysInfo, setSysInfo] = useState<any>(null);
  const [sysMetrics, setSysMetrics] = useState<any>(null);
  const [activityLogs, setActivityLogs] = useState<string[]>([]);
  const [showLogEventModal, setShowLogEventModal] = useState(false);
  const [logEventForm, setLogEventForm] = useState({
    severity: 'medium',
    category: 'Suspicious Behavior',
    title: '',
    details: '',
    source: 'Security Operations',
    ip: '',
  });

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
    const interval = setInterval(fetchSecurityEvents, 8000); // Poll every 8 seconds
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
    const bi = setInterval(fetchBlocked, 20000);
    return () => clearInterval(bi);
  }, [token]);

  // Live network/system topology info
  useEffect(() => {
    const fetchInfo = async () => {
      try {
        const resp = await axios.get('/api/system/info');
        setSysInfo(resp.data);
      } catch (err) {
        // ignore transient failures
      }
    };
    fetchInfo();
    const t = setInterval(fetchInfo, 30000);
    return () => clearInterval(t);
  }, []);

  // Live host performance metrics
  useEffect(() => {
    let alive = true;
    const fetchMetrics = async () => {
      try {
        const resp = await axios.get('/api/system/metrics');
        if (alive) setSysMetrics(resp.data);
      } catch (err) {
        // ignore transient failures
      }
    };
    fetchMetrics();
    const t = setInterval(fetchMetrics, 5000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  // Admin activity log (merged Diagnostics panel)
  useEffect(() => {
    let alive = true;
    const fetchLogs = async () => {
      try {
        const resp = await axios.get('/api/admin/logs/admin_dashboard_actions', {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (alive && resp.data.logs) setActivityLogs(resp.data.logs);
      } catch (err) {
        // ignore transient failures
      }
    };
    fetchLogs();
    const t = setInterval(fetchLogs, 20000);
    return () => { alive = false; clearInterval(t); };
  }, [token]);

  const exportActivityLogs = () => {
    const filename = `admin_dashboard_actions_${new Date().toISOString().split('T')[0]}.log`;
    const content = activityLogs.join('\n');
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
    void logAdminActivity({
      action: 'diagnostics_logs_exported',
      eventType: 'security',
      page: 'dashboard/security',
      target: 'admin-dashboard-actions-log',
      details: { filename, count: activityLogs.length, outcome: 'success' },
    }, token);
  };

  const metricSeverityColor = (pct: number | null | undefined): string => {
    if (pct === null || pct === undefined) return 'var(--muted, #7c8794)';
    if (pct >= 85) return '#ff4545';
    if (pct >= 60) return '#ffb000';
    return '#3fb950';
  };

  const renderMetricRow = (label: string, pct: number | null | undefined, detail: string) => (
    <div className="metric-row" key={label}>
      <span className="metric-name">{label}</span>
      <div className="metric-bar-container">
        <div className="metric-bar" style={{ width: `${Math.min(100, pct ?? 0)}%`, backgroundColor: metricSeverityColor(pct) }} />
      </div>
      <span className="metric-value" style={{ color: metricSeverityColor(pct) }}>
        {pct === null || pct === undefined ? '--' : `${pct}%`}
      </span>
      <span className="metric-detail">{detail}</span>
    </div>
  );

  const getSeverityLedClass = (severity: string) => {
    switch (severity) {
      case 'critical': return 'sev-led sev-critical';
      case 'high': return 'sev-led sev-high';
      case 'medium': return 'sev-led sev-medium';
      case 'low': return 'sev-led sev-low';
      default: return 'sev-led';
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
      void logAdminActivity({
        action: 'security_alerts_cleared',
        eventType: 'security',
        page: 'dashboard/security',
        target: 'security-alerts',
        details: {
          outcome: 'success',
        },
      }, token);
      alert('✅ All security events cleared successfully');
    } catch (error) {
      console.error('Failed to clear alerts:', error);
      void logAdminActivity({
        action: 'security_alerts_clear_failed',
        eventType: 'security',
        page: 'dashboard/security',
        target: 'security-alerts',
        details: {
          outcome: 'error',
        },
      }, token);
      alert('❌ Failed to clear alerts. Please try again.');
    }
  };

  const clearLocalAlerts = () => {
    void logAdminActivity({
      action: 'security_local_alerts_cleared',
      eventType: 'security',
      page: 'dashboard/security',
      target: 'local-alerts',
      details: {
        count: alerts.length,
      },
    }, token);
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
      void logAdminActivity({
        action: 'security_events_exported',
        eventType: 'security',
        page: 'dashboard/security',
        target: 'security-events-export',
        details: {
          filename: `security_events_${new Date().toISOString().split('T')[0]}.csv`,
          outcome: 'success',
        },
      }, token);
      
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
      void logAdminActivity({
        action: 'failed_logins_exported',
        eventType: 'security',
        page: 'dashboard/security',
        target: 'failed-logins-export',
        details: {
          filename: `failed_logins_${new Date().toISOString().split('T')[0]}.csv`,
          outcome: 'success',
        },
      }, token);
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
      void logAdminActivity({
        action: 'anomalies_exported',
        eventType: 'security',
        page: 'dashboard/security',
        target: 'anomalies-export',
        details: {
          filename: `anomalies_${new Date().toISOString().split('T')[0]}.json`,
          outcome: 'success',
        },
      }, token);
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
      void logAdminActivity({
        action: 'security_alert_acknowledged',
        eventType: 'security',
        page: 'dashboard/security',
        target: 'alert-acknowledgement',
        details: {
          outcome: 'success',
          notes_present: acknowledgeNotes ? 'true' : 'false',
        },
      }, token);
      alert('✅ Alert acknowledged successfully');
    } catch (error) {
      console.error('Failed to acknowledge alert:', error);
      alert('❌ Failed to acknowledge alert. Please try again.');
    }
  };

  // Let the admin manually log a system / security-ops event for the blue
  // team to review. The server raises the event AND an HMI popup notification.
  const submitLogEvent = async () => {
    if (!logEventForm.title.trim()) {
      alert('Please provide an event title/message.');
      return;
    }
    try {
      await axios.post('/api/admin/security/events/create', {
        severity: logEventForm.severity,
        category: logEventForm.category,
        title: logEventForm.title.trim(),
        details: logEventForm.details.trim(),
        source: logEventForm.source.trim() || 'Security Operations',
        suspicious: true,
        ip: logEventForm.ip.trim() || undefined,
      }, { headers: { Authorization: `Bearer ${token}` } });
      void logAdminActivity({
        action: 'security_event_logged',
        eventType: 'security',
        page: 'dashboard/security',
        target: 'log-security-event',
        details: { severity: logEventForm.severity, category: logEventForm.category, outcome: 'success' },
      }, token);
      setShowLogEventModal(false);
      setLogEventForm({ severity: 'medium', category: 'Suspicious Behavior', title: '', details: '', source: 'Security Operations', ip: '' });
      alert('✅ Security event logged (broadcast to blue team + HMI notification)');
      // Refresh the event list right away
      try {
        const resp = await axios.get('/api/admin/security/events', { headers: { Authorization: `Bearer ${token}` } });
        if (resp.data.events) setSecurityEvents(resp.data.events);
      } catch (e) { /* ignore */ }
    } catch (error) {
      console.error('Failed to log security event:', error);
      alert('❌ Failed to log security event.');
    }
  };

  // Block an IP and revoke tokens
  const blockIp = async (ip: string) => {
    if (!ip) return;
    if (!confirm(`Block and disconnect IP ${ip}? This will revoke any active admin sessions from that IP.`)) return;
    try {
      const resp = await axios.post('/api/admin/security/block', { ip, reason: 'Manual block via Dashboard' }, { headers: { Authorization: `Bearer ${token}` } });
      void logAdminActivity({
        action: 'security_ip_blocked',
        eventType: 'security',
        page: 'dashboard/security',
        target: 'blocked-ip-list',
        details: {
          ip,
          outcome: 'success',
          count: resp.data.revoked_sessions || 0,
        },
      }, token);
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
      void logAdminActivity({
        action: 'security_ip_disconnected',
        eventType: 'security',
        page: 'dashboard/security',
        target: 'blocked-ip-list',
        details: {
          ip,
          outcome: 'success',
          count: resp.data.revoked_sessions || 0,
        },
      }, token);
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
      void logAdminActivity({
        action: 'security_ip_unblocked',
        eventType: 'security',
        page: 'dashboard/security',
        target: 'blocked-ip-list',
        details: {
          ip,
          outcome: 'success',
        },
      }, token);
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
        <div>
          <h2>SECURITY OPERATIONS CENTER</h2>
          <p className="header-sub">UNIT CY-LIM-042 · INTRUSION MONITORING &amp; DIAGNOSTICS</p>
        </div>
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

      <div className="diag-grid">
        <div className="network-status">
          <h3>NETWORK TOPOLOGY <span className="live-tag">LIVE</span></h3>
          <div className="status-grid">
            <div className="status-item">
              <div className="status-label">Controller IP</div>
              <div className="status-value mono">{sysInfo?.controller_ips?.[0] || 'resolving…'}</div>
            </div>
            <div className="status-item">
              <div className="status-label">MQTT Broker</div>
              <div className="status-value mono">
                {sysInfo ? `${sysInfo.mqtt_broker.host}:${sysInfo.mqtt_broker.port}` : '…'}
                <span className={`net-led ${sysInfo?.mqtt_broker?.connected ? 'led-ok' : 'led-crit'}`} />
              </div>
            </div>
            <div className="status-item">
              <div className="status-label">Modbus TCP</div>
              <div className="status-value mono">
                :{sysInfo?.modbus?.port ?? '15002'}
                <span className={`net-led ${sysInfo?.modbus?.listening ? 'led-ok' : 'led-crit'}`} />
              </div>
            </div>
            <div className="status-item">
              <div className="status-label">Session ID</div>
              <div className="status-value code">{systemStatus?.session || sysInfo?.session || 'N/A'}</div>
            </div>
            <div className="status-item">
              <div className="status-label">Firmware</div>
              <div className="status-value mono">{sysInfo?.firmware || '—'}</div>
            </div>
            <div className="status-item">
              <div className="status-label">Server Time</div>
              <div className="status-value mono">{sysInfo?.server_time || '—'}</div>
            </div>
          </div>
        </div>

        <div className="system-metrics">
          <h3>HOST PERFORMANCE <span className="live-tag">5S</span></h3>
          <div className="metrics-table">
            {renderMetricRow(
              'CPU Usage',
              sysMetrics?.cpu?.percent,
              `load ${sysMetrics?.load_avg?.m1 ?? '--'} / ${sysMetrics?.process?.threads ?? '--'} thr`
            )}
            {renderMetricRow(
              'Memory',
              sysMetrics?.memory?.percent,
              sysMetrics?.memory?.total_mb ? `${sysMetrics.memory.used_mb}/${sysMetrics.memory.total_mb} MB` : ''
            )}
            {renderMetricRow(
              'Network I/O',
              sysMetrics?.network?.percent,
              sysMetrics ? `↓ ${sysMetrics.network.rx_kbps} · ↑ ${sysMetrics.network.tx_kbps} KB/s` : ''
            )}
            {renderMetricRow(
              'Disk Usage',
              sysMetrics?.disk?.percent,
              sysMetrics?.disk?.total_gb ? `${sysMetrics.disk.used_gb}/${sysMetrics.disk.total_gb} GB` : ''
            )}
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
        <button className="action-btn primary" onClick={() => setShowLogEventModal(true)}>
          📝 Log Security Event
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
                    <span className={getSeverityLedClass(alert.severity)} />
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

      {showLogEventModal && (
        <div className="modal-overlay" onClick={() => setShowLogEventModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Log Security Event</h3>
            <p className="event-logging-hint">
              Record a suspicious behavior / security-ops finding. It is added to the
              security event log, broadcast to the <strong>blue team</strong> review screen,
              and raises an <strong>HMI popup notification</strong>.
            </p>
            <div className="modal-body">
              <label className="form-label">Severity</label>
              <select
                value={logEventForm.severity}
                onChange={(e) => setLogEventForm(f => ({ ...f, severity: e.target.value }))}
                style={{ width: '100%', padding: '8px', marginBottom: '10px' }}
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>

              <label className="form-label">Category</label>
              <input
                type="text"
                value={logEventForm.category}
                onChange={(e) => setLogEventForm(f => ({ ...f, category: e.target.value }))}
                placeholder="e.g. Suspicious Behavior, Phishing, Data Integrity"
                style={{ width: '100%', padding: '8px', marginBottom: '10px' }}
              />

              <label className="form-label">Title / Message <span style={{ color: '#ff5252' }}>*</span></label>
              <input
                type="text"
                value={logEventForm.title}
                onChange={(e) => setLogEventForm(f => ({ ...f, title: e.target.value }))}
                placeholder="What happened?"
                style={{ width: '100%', padding: '8px', marginBottom: '10px' }}
              />

              <label className="form-label">Details</label>
              <textarea
                value={logEventForm.details}
                onChange={(e) => setLogEventForm(f => ({ ...f, details: e.target.value }))}
                rows={3}
                placeholder="Additional context, indicators, remediation..."
                style={{ width: '100%', padding: '8px', marginBottom: '10px' }}
              />

              <label className="form-label">Source</label>
              <input
                type="text"
                value={logEventForm.source}
                onChange={(e) => setLogEventForm(f => ({ ...f, source: e.target.value }))}
                style={{ width: '100%', padding: '8px', marginBottom: '10px' }}
              />

              <label className="form-label">IP (optional)</label>
              <input
                type="text"
                value={logEventForm.ip}
                onChange={(e) => setLogEventForm(f => ({ ...f, ip: e.target.value }))}
                placeholder="e.g. 203.0.113.7"
                style={{ width: '100%', padding: '8px' }}
              />
            </div>
            <div className="modal-actions">
              <button className="btn-primary" onClick={submitLogEvent}>
                Log Event
              </button>
              <button className="btn-secondary" onClick={() => setShowLogEventModal(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="diag-grid">
        <div className="event-history">
          <h3>RECENT EVENTS</h3>
          <div className="events-list">
            {securityEvents.slice(0, 6).length === 0 ? (
              <div className="event-item event-info">
                <div className="event-indicator" />
                <div className="event-content">
                  <div className="event-title">No security events recorded</div>
                  <div className="event-time">Monitor running…</div>
                </div>
              </div>
            ) : (
              securityEvents.slice(0, 6).map((ev: any) => (
                <div key={ev.timestamp} className={`event-item ${ev.severity === 'critical' || ev.severity === 'high' ? 'event-critical' : 'event-warning'}`}>
                  <div className="event-indicator" />
                  <div className="event-content">
                    <div className="event-title">{ev.message}</div>
                    <div className="event-time">{new Date(ev.timestamp).toLocaleString()}</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="logs-panel">
          <div className="logs-header">
            <h3>ADMIN ACTIVITY LOG</h3>
            <div className="log-controls">
              <button className="control-btn" onClick={exportActivityLogs}>EXPORT</button>
            </div>
          </div>
          <div className="logs-container">
            {activityLogs.length > 0 ? (
              activityLogs.map((log, index) => (
                <div key={index} className="log-entry">
                  <span className="log-message">{log}</span>
                </div>
              ))
            ) : (
              <div className="log-entry">
                <span className="log-message log-info">No admin dashboard actions have been logged yet</span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="investigation-tips">
        <h3>🔍 Investigation Guide</h3>
        <div className="tips-content">
          <div className="tip-item">
            <strong>When you see anomalies:</strong>
            <ul>
              <li>Check the Power Analytics view for unusual patterns</li>
              <li>Review the topology and activity panels on this page</li>
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
