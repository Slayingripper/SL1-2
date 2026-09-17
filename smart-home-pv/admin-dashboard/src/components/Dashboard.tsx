import React, { useState, useEffect, useRef } from 'react';
import mqtt from 'mqtt';
import axios from 'axios';
import SystemOverview from './SystemOverview';
import AreaMap from './AreaMap';
import PowerChart from './PowerChart';
import ModbusControl from './ModbusControl';
import SecurityAlerts from './SecurityAlerts';
import NotificationPopup from './NotificationPopup';
import './Dashboard.css';
import { logAdminActivity, useAdminActivityCapture } from '../utils/activityLogger';

interface DashboardProps {
  token: string;
  onLogout: () => void;
}

interface MQTTStatus {
  status: string;
  session: string;
  power?: number;
  power_kw?: number;
  voltage_v?: number;
  current_a?: number;
  uptime_s?: number;
  timestamp?: number;
}

interface MQTTTelemetry {
  timestamp: number;
  power_kw: number;
  voltage_v?: number;
  current_a?: number;
}

export interface SeederInfo {
  container?: string;
  ip?: string;
  pid?: number;
  interval_s?: number;
  topic?: string;
  started_ts?: number;
  seq?: number;
  uptime_s?: number;
}

export interface SiteTelemetry {
  site?: string;
  ts?: number;
  power_kw?: number;
  load_kw?: number;
  voltage_v?: number;
  current_a?: number;
  status?: string;
  seeder?: SeederInfo;
}

export interface SiteLive {
  latest: SiteTelemetry | null;
  history: SiteTelemetry[];
}

interface ActiveDefense {
  telemetry_validation: boolean;
  telemetry_min_kw: number;
  telemetry_max_kw: number;
}

const Dashboard: React.FC<DashboardProps> = ({ token, onLogout }) => {
  const [activeView, setActiveView] = useState('overview');
  const [mqttConnected, setMqttConnected] = useState(false);
  const [systemStatus, setSystemStatus] = useState<MQTTStatus | null>(null);
  const [telemetryData, setTelemetryData] = useState<MQTTTelemetry[]>([]);
  const [siteData, setSiteData] = useState<Record<string, SiteLive>>({});
  const [currentTime, setCurrentTime] = useState(new Date());
  const [defense, setDefense] = useState<ActiveDefense>({
    telemetry_validation: false,
    telemetry_min_kw: -2,
    telemetry_max_kw: 10,
  });
  const defenseRef = useRef(defense);
  useEffect(() => { defenseRef.current = defense; }, [defense]);

  useAdminActivityCapture(`dashboard/${activeView}`, token);

  // Mirrors the blue-team Telemetry Validation control: the operator console
  // subscribes to MQTT directly, so it re-applies the same bounds as the
  // controller to guarantee attacker-injected readings never reach the charts.
  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const resp = await axios.get('/api/blueteam/defense_status');
        const d = resp.data || {};
        if (alive) {
          setDefense({
            telemetry_validation: !!d.telemetry_validation,
            telemetry_min_kw: typeof d.telemetry_min_kw === 'number' ? d.telemetry_min_kw : -2,
            telemetry_max_kw: typeof d.telemetry_max_kw === 'number' ? d.telemetry_max_kw : 10,
          });
        }
      } catch (error) {
        console.debug('Failed to fetch defense status:', error);
      }
    };
    poll();
    const iv = setInterval(poll, 10000);
    return () => { alive = false; clearInterval(iv); };
  }, []);

  useEffect(() => {
    // Connect to the MQTT broker over WebSockets. Depending on where the
    // browser runs, the broker is reachable under different names:
    //  - from the host / LAN: the published port 9001 on the accessed hostname
    //  - from inside the docker network: the "mosquitto" service name
    // Try candidates in order until one connects.
    const hostname = window.location.hostname;
    const candidates = Array.from(new Set([
      `${hostname === '' ? 'localhost' : hostname}`,
      'mosquitto',
      'localhost',
    ])).map(h => `ws://${h}:9001`);

    let client: ReturnType<typeof mqtt.connect> | null = null;
    let disposed = false;
    let idx = 0;

    const connectNext = () => {
      if (disposed || idx >= candidates.length) return;
      const mqttUrl = candidates[idx++];
      let everConnected = false;
      client = mqtt.connect(mqttUrl, { reconnectPeriod: 0, connectTimeout: 4000 });

      client.on('connect', () => {
        if (disposed) return;
        setMqttConnected(true);
        void logAdminActivity({
          action: 'mqtt_connected',
          eventType: 'system',
          page: 'dashboard',
          target: 'mqtt-broker',
          details: {
            status: 'connected',
            destination: mqttUrl,
          },
        }, token);
        client?.subscribe('pv/status');
        client?.subscribe('pv/telemetry');
        // Area map: per-site live feed + retained seed history
        client?.subscribe('pv/telemetry/+');
        client?.subscribe('pv/history/+');
      });

      client.on('message', (_topic, message) => {
        try {
          const data = JSON.parse(message.toString());

          if (_topic === 'pv/status') {
            setSystemStatus(data);
          } else if (_topic === 'pv/telemetry') {
            const dv = defenseRef.current;
            if (dv.telemetry_validation) {
              const raw = data.power_kw !== undefined ? data.power_kw : data.power;
              const ok = typeof raw === 'number' && raw >= dv.telemetry_min_kw && raw <= dv.telemetry_max_kw;
              if (!ok) {
                console.debug('Telemetry validation dropped reading from direct MQTT', data);
                return;
              }
            }
            setTelemetryData(prev => {
              const newData = [...prev, data];
              // Keep last 60 data points for the charts
              return newData.slice(-60);
            });
          } else if (_topic.startsWith('pv/telemetry/')) {
            // Area-map site feed. The blue-team telemetry-validation gate above
            // is scoped to the plant's pv/telemetry topic only.
            const id = _topic.split('/')[2];
            if (id) {
              setSiteData(prev => {
                const cur = prev[id] || { latest: null, history: [] };
                return {
                  ...prev,
                  [id]: { latest: data, history: [...cur.history, data].slice(-120) },
                };
              });
            }
          } else if (_topic.startsWith('pv/history/')) {
            const id = _topic.split('/')[2];
            if (id && Array.isArray(data.points)) {
              setSiteData(prev => {
                const cur = prev[id] || { latest: null, history: [] };
                // Retained seed history only fills an empty series — never
                // clobber live accumulation on reconnect.
                if (cur.history.length >= 5) return prev;
                return { ...prev, [id]: { ...cur, history: data.points.slice(-120) } };
              });
            }
          }
        } catch (error) {
          console.error('Error parsing MQTT message:', error);
        }
      });

      client.on('error', (error) => {
        console.debug(`MQTT endpoint failed (${mqttUrl}):`, error.message);
      });

      // Never connected successfully -> fall back to the next candidate
      client.on('close', () => {
        if (disposed) return;
        setMqttConnected(false);
        if (!everConnected && idx < candidates.length) {
          client?.end(true);
          connectNext();
        }
      });
    };

    connectNext();

    // Update clock every 5 seconds to reduce unnecessary re-renders
    const clockInterval = setInterval(() => {
      setCurrentTime(new Date());
    }, 5000);

    return () => {
      disposed = true;
      client?.end(true);
      clearInterval(clockInterval);
    };
  }, [token]);

  const handleResetPlant = async () => {
    try {
      await axios.post('/api/plant/reset', {}, {
        headers: { Authorization: `Bearer ${token}` },
      });
      void logAdminActivity({
        action: 'plant_reset',
        eventType: 'system',
        page: `dashboard/${activeView}`,
        target: 'reset-plant-button',
        details: { outcome: 'success', status: 'RUNNING' },
      }, token);
      // MQTT status republishes shortly; also refresh from HTTP so the badge
      // flips back immediately.
      try {
        const { data } = await axios.get('/api/status');
        setSystemStatus(prev => ({ ...(prev || ({} as MQTTStatus)), status: data.status }));
      } catch (e) { /* ignore */ }
    } catch (error: any) {
      console.error('Failed to reset plant:', error);
      alert('❌ Failed to reset plant.');
    }
  };

  const handleLogout = () => {
    void logAdminActivity({
      action: 'logout_requested',
      eventType: 'authentication',
      page: `dashboard/${activeView}`,
      target: 'logout-button',
      details: {
        outcome: 'initiated',
      },
    }, token);
    // If blue-team defenses are active, reset them on logoff (training scenario)
    void axios.post('/api/blueteam/logout', {}, {
      headers: { Authorization: `Bearer ${token}` },
    }).catch(() => { /* best effort */ });
    localStorage.removeItem('pv_admin_token');
    localStorage.removeItem('pv_admin_role');
    onLogout();
  };

  const handleViewChange = (view: string) => {
    void logAdminActivity({
      action: 'dashboard_view_changed',
      eventType: 'navigation',
      page: `dashboard/${activeView}`,
      target: 'sidebar-navigation',
      details: {
        view,
        destination: view,
      },
    }, token);
    setActiveView(view);
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

  const halted = String(systemStatus?.status || '').toUpperCase() === 'HALTED';
  const healthPct = halted ? 18 : mqttConnected ? 94 + (Math.abs(Math.round(systemStatus?.power_kw ?? 0) * 7) % 5) : 62;
  const uptimeStr = (() => {
    const s = Number(systemStatus?.uptime_s ?? 0);
    if (!s) return '—';
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    return d > 0 ? `${d}d ${h}h ${m}m` : `${h}h ${m}m`;
  })();

  return (
    <div className="dashboard">
      {/* Notification Pop-ups */}
      <NotificationPopup />
      <header className="dashboard-header">
        <div className="header-left">
          <div className="header-logo">
            <span className="logo-mark">PV</span>
            <div className="logo-text">
              <h1>PV SCADA HMI</h1>
              <p>UNIT CY-LIM-042 · LIMASSOL SOLAR PLANT</p>
            </div>
          </div>
          <div className="hazard-strip" />
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
              {mqttConnected ? 'TELEMETRY LINK' : 'LINK FAULT'}
            </span>
          </div>
          {halted && (
            <button className="reset-plant-button" onClick={handleResetPlant}>
              ♻️ RESET PLANT
            </button>
          )}
          <button className="logout-button" onClick={handleLogout}>
            LOGOUT
          </button>
        </div>
      </header>

      <div className="dashboard-body">
        <aside className="sidebar">
          <nav className="sidebar-nav">
            <button 
              className={`nav-item ${activeView === 'overview' ? 'active' : ''}`}
              onClick={() => handleViewChange('overview')}
            >
              <span className="nav-index">01</span>
              <span className="nav-label">Plant Overview</span>
              <span className={`nav-led nav-led-ok`} />
            </button>
            <button
              className={`nav-item ${activeView === 'areamap' ? 'active' : ''}`}
              onClick={() => handleViewChange('areamap')}
            >
              <span className="nav-index">02</span>
              <span className="nav-label">Area Map</span>
              <span className={`nav-led nav-led-ok`} />
            </button>
            <button
              className={`nav-item ${activeView === 'power' ? 'active' : ''}`}
              onClick={() => handleViewChange('power')}
            >
              <span className="nav-index">03</span>
              <span className="nav-label">Power Analytics</span>
              <span className={`nav-led nav-led-ok`} />
            </button>
            <button
              className={`nav-item ${activeView === 'modbus' ? 'active' : ''}`}
              onClick={() => handleViewChange('modbus')}
            >
              <span className="nav-index">04</span>
              <span className="nav-label">Modbus Control</span>
              <span className={`nav-led ${halted ? 'nav-led-crit' : 'nav-led-ok'}`} />
            </button>
            <button
              className={`nav-item ${activeView === 'security' ? 'active' : ''}`}
              onClick={() => handleViewChange('security')}
            >
              <span className="nav-index">05</span>
              <span className="nav-label">Security Ops</span>
              <span className="nav-led nav-led-amb" />
            </button>
          </nav>

          <div className="sidebar-footer">
            <div className="system-health">
              <div className="health-indicator">
                <span className="health-label">System Health</span>
                <div className="health-bar">
                  <div className={`health-fill ${halted ? 'health-halted' : ''}`} style={{width: `${healthPct}%`}}></div>
                </div>
                <span className="health-value">{healthPct}%</span>
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
                now={currentTime}
                siteData={siteData}
                token={token}
              />
            )}
            {activeView === 'areamap' && (
              <AreaMap siteData={siteData} token={token} mqttConnected={mqttConnected} />
            )}
            {activeView === 'power' && (
              <PowerChart telemetryData={telemetryData} />
            )}
            {activeView === 'modbus' && (
              <ModbusControl token={token} siteData={siteData} />
            )}
            {activeView === 'security' && (
              <SecurityAlerts token={token} telemetryData={telemetryData} systemStatus={systemStatus} />
            )}
          </div>
        </main>
      </div>

      <footer className="dashboard-footer">
        <div className="footer-info">
          <span>PV Controller v2.4.1</span>
          <span>|</span>
          <span>Uptime: {uptimeStr}</span>
          <span>|</span>
          <span>Site: CY-LIM-042 · Cyprus</span>
        </div>
        <div className="footer-status">
          <span className="footer-led" />
          <span className={`status-badge ${halted ? 'status-halted' : 'status-operational'}`}>
            {halted ? 'PLANT HALTED — INCIDENT ACTIVE' : 'ALL SYSTEMS OPERATIONAL'}
          </span>
        </div>
      </footer>
    </div>
  );
};

export default Dashboard;
