import React from 'react';
import './SystemOverview.css';

interface SystemOverviewProps {
  systemStatus: any;
  telemetryData: any[];
  mqttConnected: boolean;
}

const SystemOverview: React.FC<SystemOverviewProps> = ({ 
  systemStatus, 
  telemetryData,
  mqttConnected 
}) => {
  const currentPower = systemStatus?.power_kw || systemStatus?.power || 0;
  const systemState = systemStatus?.status || 'UNKNOWN';
  const latestTelemetry = telemetryData[telemetryData.length - 1];
  
  const avgPower = telemetryData.length > 0
    ? telemetryData.reduce((sum, d) => sum + (d.power_kw || d.power || d.value || 0), 0) / telemetryData.length
    : 0;

  return (
    <div className="system-overview">
      <div className="page-header">
        <h2>System Overview</h2>
        <p>Real-time monitoring and control</p>
      </div>

      <div className="metrics-grid">
        <div className="metric-card metric-primary">
          <div className="metric-icon">⚡</div>
          <div className="metric-content">
            <div className="metric-label">Current Power Output</div>
            <div className="metric-value">{currentPower.toFixed(2)} <span className="metric-unit">kW</span></div>
            <div className="metric-trend trend-up">↗ +12% from average</div>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon">📊</div>
          <div className="metric-content">
            <div className="metric-label">System Status</div>
            <div className={`metric-value status-${systemState.toLowerCase()}`}>
              {systemState}
            </div>
            <div className="metric-info">
              {mqttConnected ? 'Live data stream active' : 'Waiting for data'}
            </div>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon">📈</div>
          <div className="metric-content">
            <div className="metric-label">Average Power (Session)</div>
            <div className="metric-value">{avgPower.toFixed(2)} <span className="metric-unit">kW</span></div>
            <div className="metric-info">{telemetryData.length} data points</div>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon">🔌</div>
          <div className="metric-content">
            <div className="metric-label">Grid Connection</div>
            <div className="metric-value status-connected">CONNECTED</div>
            <div className="metric-info">Voltage: 240V AC</div>
          </div>
        </div>
      </div>

      <div className="info-panels">
        <div className="info-panel">
          <h3>System Information</h3>
          <div className="info-grid">
            <div className="info-row">
              <span className="info-key">Controller Model:</span>
              <span className="info-value">SolarEdge SE7600H-US</span>
            </div>
            <div className="info-row">
              <span className="info-key">Firmware Version:</span>
              <span className="info-value">4.12.34</span>
            </div>
            <div className="info-row">
              <span className="info-key">Installation Date:</span>
              <span className="info-value">2024-03-15</span>
            </div>
            <div className="info-row">
              <span className="info-key">Capacity:</span>
              <span className="info-value">7.6 kW</span>
            </div>
            <div className="info-row">
              <span className="info-key">Panel Count:</span>
              <span className="info-value">20 modules</span>
            </div>
            <div className="info-row">
              <span className="info-key">MQTT Session:</span>
              <span className="info-value code">{systemStatus?.session || 'N/A'}</span>
            </div>
          </div>
        </div>

        <div className="info-panel">
          <h3>Latest Telemetry</h3>
          <div className="telemetry-display">
            {latestTelemetry ? (
              <>
                <div className="telemetry-row">
                  <span className="telemetry-key">Timestamp:</span>
                  <span className="telemetry-value">
                    {new Date((latestTelemetry.timestamp || latestTelemetry.ts) * 1000).toLocaleString()}
                  </span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-key">Power Output:</span>
                  <span className="telemetry-value">{(latestTelemetry.power_kw || latestTelemetry.power || 0).toFixed(2)} kW</span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-key">Voltage:</span>
                  <span className="telemetry-value">{latestTelemetry.voltage_v || 'N/A'} V</span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-key">Current:</span>
                  <span className="telemetry-value">{latestTelemetry.current_a ? latestTelemetry.current_a.toFixed(1) : 'N/A'} A</span>
                </div>
              </>
            ) : (
              <div className="no-data">Waiting for telemetry data...</div>
            )}
          </div>
        </div>
      </div>

      <div className="alert-section">
        <h3>System Alerts & Notifications</h3>
        <div className="alert-list">
          <div className="alert alert-info">
            <span className="alert-icon">ℹ️</span>
            <div className="alert-content">
              <div className="alert-title">System Online</div>
              <div className="alert-message">PV controller operating normally. All systems functional.</div>
              <div className="alert-time">2 minutes ago</div>
            </div>
          </div>
          <div className="alert alert-success">
            <span className="alert-icon">✓</span>
            <div className="alert-content">
              <div className="alert-title">Peak Production Reached</div>
              <div className="alert-message">System reached 98% of rated capacity at 12:34 PM</div>
              <div className="alert-time">1 hour ago</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SystemOverview;
