import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './Diagnostics.css';
import { logAdminActivity } from '../utils/activityLogger';

interface DiagnosticsProps {
  token: string;
  systemStatus: any;
}

const Diagnostics: React.FC<DiagnosticsProps> = ({ token, systemStatus }) => {
  const [logs, setLogs] = useState<string[]>([]);
  const [flag, setFlag] = useState('');

  const fetchLogs = async (reason: 'initial' | 'poll' | 'manual' = 'poll') => {
    try {
      const response = await axios.get('/api/admin/logs/admin_dashboard_actions', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.data.logs) {
        setLogs(response.data.logs);
      }
      if (reason !== 'poll') {
        void logAdminActivity({
          action: 'diagnostics_logs_refreshed',
          eventType: 'diagnostics',
          page: 'dashboard/diagnostics',
          target: 'admin-dashboard-actions-log',
          details: {
            outcome: 'success',
            count: response.data.logs?.length || 0,
          },
        }, token);
      }
    } catch (error) {
      console.error('Error fetching logs:', error);
      if (reason !== 'poll') {
        void logAdminActivity({
          action: 'diagnostics_logs_refresh_failed',
          eventType: 'diagnostics',
          page: 'dashboard/diagnostics',
          target: 'admin-dashboard-actions-log',
          details: {
            outcome: 'error',
          },
        }, token);
      }
    }
  };

  const exportLogs = async () => {
    const filename = `admin_dashboard_actions_${new Date().toISOString().split('T')[0]}.log`;
    const content = logs.join('\n');
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
      eventType: 'diagnostics',
      page: 'dashboard/diagnostics',
      target: 'admin-dashboard-actions-log',
      details: {
        filename,
        count: logs.length,
        outcome: 'success',
      },
    }, token);
  };

  useEffect(() => {
    // Fetch the flag after successful authentication
    const fetchFlag = async () => {
      try {
        const response = await axios.get('/api/admin/flag', {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (response.data.flag) {
          setFlag(response.data.flag);
        }
      } catch (error) {
        console.error('Error fetching flag:', error);
      }
    };

    fetchFlag();
    fetchLogs('initial');

    // Refresh logs every 20 seconds to reduce polling overhead
    const interval = setInterval(() => {
      void fetchLogs('poll');
    }, 20000);
    return () => clearInterval(interval);
  }, [token]);

  return (
    <div className="diagnostics">
      <div className="page-header">
        <h2>System Diagnostics</h2>
        <p>Advanced monitoring and troubleshooting</p>
      </div>

      {flag && (
        <div className="flag-panel">
          <div className="flag-header">
            <span className="flag-icon">🏁</span>
            <h3>Achievement Unlocked</h3>
          </div>
          <div className="flag-content">
            <div className="flag-label">Admin Access Flag</div>
            <div className="flag-value">{flag}</div>
            <div className="flag-message">
              Congratulations! You have successfully gained administrative access to the PV SCADA system.
            </div>
          </div>
        </div>
      )}

      <div className="network-status">
        <h3>Network Status</h3>
        <div className="status-grid">
          <div className="status-item">
            <div className="status-icon">🌐</div>
            <div className="status-details">
              <div className="status-label">Controller IP</div>
              <div className="status-value">172.20.0.65</div>
            </div>
          </div>
          <div className="status-item">
            <div className="status-icon">📡</div>
            <div className="status-details">
              <div className="status-label">MQTT Broker</div>
              <div className="status-value">172.20.0.66:1883</div>
            </div>
          </div>
          <div className="status-item">
            <div className="status-icon">🔧</div>
            <div className="status-details">
              <div className="status-label">Modbus Port</div>
              <div className="status-value">502 (TCP)</div>
            </div>
          </div>
          <div className="status-item">
            <div className="status-icon">🔒</div>
            <div className="status-details">
              <div className="status-label">Session</div>
              <div className="status-value code">{systemStatus?.session || 'N/A'}</div>
            </div>
          </div>
        </div>
      </div>

      <div className="logs-panel">
        <div className="logs-header">
          <h3>Admin Activity Logs</h3>
          <div className="log-controls">
            <button className="control-btn" onClick={() => void fetchLogs('manual')}>
              <span>🔄</span>
              Refresh
            </button>
            <button className="control-btn" onClick={exportLogs}>
              <span>⬇️</span>
              Export
            </button>
          </div>
        </div>
        <div className="logs-container">
          {logs.length > 0 ? (
            logs.map((log, index) => (
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

      <div className="system-metrics">
        <h3>Performance Metrics</h3>
        <div className="metrics-table">
          <div className="metric-row">
            <span className="metric-name">CPU Usage</span>
            <div className="metric-bar-container">
              <div className="metric-bar" style={{width: '34%'}}></div>
            </div>
            <span className="metric-value">34%</span>
          </div>
          <div className="metric-row">
            <span className="metric-name">Memory Usage</span>
            <div className="metric-bar-container">
              <div className="metric-bar" style={{width: '58%'}}></div>
            </div>
            <span className="metric-value">58%</span>
          </div>
          <div className="metric-row">
            <span className="metric-name">Network I/O</span>
            <div className="metric-bar-container">
              <div className="metric-bar" style={{width: '22%'}}></div>
            </div>
            <span className="metric-value">22%</span>
          </div>
          <div className="metric-row">
            <span className="metric-name">Disk Usage</span>
            <div className="metric-bar-container">
              <div className="metric-bar" style={{width: '47%'}}></div>
            </div>
            <span className="metric-value">47%</span>
          </div>
        </div>
      </div>

      <div className="event-history">
        <h3>Recent Events</h3>
        <div className="events-list">
          <div className="event-item event-critical">
            <div className="event-indicator"></div>
            <div className="event-content">
              <div className="event-title">Admin Login Detected</div>
              <div className="event-time">Just now</div>
            </div>
          </div>
          <div className="event-item event-warning">
            <div className="event-indicator"></div>
            <div className="event-content">
              <div className="event-title">Unusual Access Pattern</div>
              <div className="event-time">2 minutes ago</div>
            </div>
          </div>
          <div className="event-item event-info">
            <div className="event-indicator"></div>
            <div className="event-content">
              <div className="event-title">System Health Check Passed</div>
              <div className="event-time">15 minutes ago</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Diagnostics;
