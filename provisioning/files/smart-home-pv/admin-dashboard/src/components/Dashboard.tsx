import React, { useState, useEffect } from 'react';
import mqtt from 'mqtt';
import SystemOverview from './SystemOverview';
import PowerChart from './PowerChart';
import ModbusControl from './ModbusControl';
import Diagnostics from './Diagnostics';
import SecurityAlerts from './SecurityAlerts';
import NotificationPopup from './NotificationPopup';
import ContainerSwitcher from './ContainerSwitcher';
import './Dashboard.css';

interface DashboardProps {
  token: string;
  onLogout: () => void;
}

interface MQTTStatus {
  status: string;
  session: string;
  power: number;
  timestamp?: number;
}

interface MQTTTelemetry {
  timestamp: number;
  power_kw: number;
  voltage_v?: number;
  current_a?: number;
}

const Dashboard: React.FC<DashboardProps> = ({ token, onLogout }) => {
  const [activeView, setActiveView] = useState('overview');
  const [mqttConnected, setMqttConnected] = useState(false);
  const [systemStatus, setSystemStatus] = useState<MQTTStatus | null>(null);
  const [telemetryData, setTelemetryData] = useState<MQTTTelemetry[]>([]);
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    // Connect to MQTT broker - if local, use localhost, otherwise connect to the host running the dashboard
    const mqttHost = window.location.hostname;
    const mqttUrl = (mqttHost === 'localhost' || mqttHost === '127.0.0.1')
      ? 'ws://localhost:9001'
      : `ws://${mqttHost}:9001`;
    
    const client = mqtt.connect(mqttUrl);

    client.on('connect', () => {
      setMqttConnected(true);
      client.subscribe('pv/status');
      client.subscribe('pv/telemetry');
    });

    client.on('message', (topic, message) => {
      try {
        const data = JSON.parse(message.toString());
        
        if (topic === 'pv/status') {
          setSystemStatus(data);
        } else if (topic === 'pv/telemetry') {
          setTelemetryData(prev => {
            const newData = [...prev, data];
            // Keep last 30 data points to reduce browser memory footprint
            return newData.slice(-30);
          });
        }
      } catch (error) {
        console.error('Error parsing MQTT message:', error);
      }
    });

    client.on('error', (error) => {
      console.error('MQTT connection error:', error);
      setMqttConnected(false);
    });

    // Update clock every 5 seconds to reduce unnecessary re-renders
    const clockInterval = setInterval(() => {
      setCurrentTime(new Date());
    }, 5000);

    return () => {
      client.end();
      clearInterval(clockInterval);
    };
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('pv_admin_token');
    onLogout();
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString('en-US', { 
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const formatDate = (date: Date) => {
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  return (
    <div className="dashboard">
      {/* Notification Pop-ups */}
      <NotificationPopup />
      {/* Container switcher cog */}
      <div style={{display: 'flex', alignItems: 'center', gap: '6px', paddingLeft: '12px'}}>
        <ContainerSwitcher />
      </div>
      
      <header className="dashboard-header">
        <div className="header-left">
          <div className="header-logo">
            <span className="logo-icon">⚡</span>
            <div className="logo-text">
              <h1>PV SCADA HMI</h1>
              <p>Solar Energy Management System</p>
            </div>
          </div>
        </div>
        
        <div className="header-center">
          <div className="system-time">
            <div className="time-display">{formatTime(currentTime)}</div>
            <div className="date-display">{formatDate(currentTime)}</div>
          </div>
        </div>

        <div className="header-right">
          <div className="connection-status">
            <span className={`status-dot ${mqttConnected ? 'connected' : 'disconnected'}`}></span>
            <span className="status-text">
              {mqttConnected ? 'MQTT Connected' : 'MQTT Disconnected'}
            </span>
          </div>
          <button className="logout-button" onClick={handleLogout}>
            <span>🚪</span>
            Logout
          </button>
        </div>
      </header>

      <div className="dashboard-body">
        <aside className="sidebar">
          <nav className="sidebar-nav">
            <button 
              className={`nav-item ${activeView === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveView('overview')}
            >
              <span className="nav-icon">📊</span>
              <span className="nav-label">System Overview</span>
            </button>
            <button 
              className={`nav-item ${activeView === 'power' ? 'active' : ''}`}
              onClick={() => setActiveView('power')}
            >
              <span className="nav-icon">⚡</span>
              <span className="nav-label">Power Analytics</span>
            </button>
            <button 
              className={`nav-item ${activeView === 'modbus' ? 'active' : ''}`}
              onClick={() => setActiveView('modbus')}
            >
              <span className="nav-icon">🔧</span>
              <span className="nav-label">Modbus Control</span>
            </button>
            <button 
              className={`nav-item ${activeView === 'diagnostics' ? 'active' : ''}`}
              onClick={() => setActiveView('diagnostics')}
            >
              <span className="nav-icon">🔍</span>
              <span className="nav-label">Diagnostics</span>
            </button>
            <button 
              className={`nav-item ${activeView === 'security' ? 'active' : ''}`}
              onClick={() => setActiveView('security')}
            >
              <span className="nav-icon">🛡️</span>
              <span className="nav-label">Security Alerts</span>
            </button>
          </nav>

          <div className="sidebar-footer">
            <div className="system-health">
              <div className="health-indicator">
                <span className="health-label">System Health</span>
                <div className="health-bar">
                  <div className="health-fill" style={{width: '94%'}}></div>
                </div>
                <span className="health-value">94%</span>
              </div>
            </div>
          </div>
        </aside>

        <main className="main-content">
          <div className="content-wrapper">
            {activeView === 'overview' && (
              <SystemOverview 
                systemStatus={systemStatus} 
                telemetryData={telemetryData}
                mqttConnected={mqttConnected}
              />
            )}
            {activeView === 'power' && (
              <PowerChart telemetryData={telemetryData} />
            )}
            {activeView === 'modbus' && (
              <ModbusControl token={token} />
            )}
            {activeView === 'diagnostics' && (
              <Diagnostics token={token} systemStatus={systemStatus} />
            )}
            {activeView === 'security' && (
              <SecurityAlerts token={token} telemetryData={telemetryData} />
            )}
          </div>
        </main>
      </div>

      <footer className="dashboard-footer">
        <div className="footer-info">
          <span>PV Controller v2.4.1</span>
          <span>|</span>
          <span>Uptime: 47d 12h 34m</span>
          <span>|</span>
          <span>Region: Cyprus</span>
        </div>
        <div className="footer-status">
          <span className="status-badge status-operational">All Systems Operational</span>
        </div>
      </footer>
    </div>
  );
};

export default Dashboard;
