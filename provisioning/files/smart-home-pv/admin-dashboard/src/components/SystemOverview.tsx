import React, { useState, useEffect } from 'react';
import SolarScene from './SolarScene';
import './SystemOverview.css';

interface SystemOverviewProps {
  systemStatus: any;
  telemetryData: any[];
  mqttConnected: boolean;
  now?: Date;
}

interface DashNotification {
  id: number;
  timestamp: string;
  title: string;
  message: string;
  read: boolean;
}

const CAPACITY_KW = 4.8;
const SUNRISE_H = 6.5;
const SUNSET_H = 19.5;
const GRID_CO2_FACTOR = 0.41; // kg CO2 per kWh displaced
const TARIFF_EUR = 0.15; // EUR per kWh

const localHours = (d: Date) => d.getHours() + d.getMinutes() / 60 + d.getSeconds() / 3600;

/** Same daylight model as the controller simulation - keeps numbers consistent */
const elevationFactor = (h: number) => {
  if (h <= SUNRISE_H || h >= SUNSET_H) return 0;
  const x = (h - SUNRISE_H) / (SUNSET_H - SUNRISE_H);
  return Math.max(0, Math.pow(Math.sin(Math.PI * x), 1.35));
};

/** Estimated energy produced today (kWh) by integrating the daylight curve */
const estimateTodayKwh = (peakKw: number) => {
  const now = new Date();
  const h = localHours(now);
  let wh = 0;
  const stepH = 0.25;
  for (let t = SUNRISE_H; t < Math.min(h, SUNSET_H); t += stepH) {
    wh += peakKw * elevationFactor(t) * stepH * 60;
  }
  return wh / 1000;
};

const batterySoc = () => {
  const now = new Date();
  const h = localHours(now);
  if (h >= SUNRISE_H && h < SUNSET_H) {
    const p = (h - SUNRISE_H) / (SUNSET_H - SUNRISE_H);
    return Math.round(45 + 48 * p); // charging through the day
  }
  if (h >= SUNSET_H) return Math.max(32, Math.round(93 - (h - SUNSET_H) * 7)); // evening discharge
  return Math.max(24, Math.round(34 - (SUNRISE_H - h) * 4)); // pre-dawn
};

const PowerChartMini: React.FC<{ peakKw: number; halted: boolean }> = ({ peakKw, halted }) => {
  // SVG sparkline of today's production curve with a live "now" marker
  const W = 560;
  const H = 130;
  const pad = 6;
  const pts: string[] = [];
  const N = 64;
  const now = new Date();
  const hNow = localHours(now);
  const scale = Math.max(peakKw, 1);
  let nowX = pad;
  for (let i = 0; i <= N; i++) {
    const frac = i / N;
    const h = SUNRISE_H + frac * (SUNSET_H - SUNRISE_H);
    const v = halted ? 0 : Math.min(1, elevationFactor(h) * CAPACITY_KW / scale);
    const x = pad + frac * (W - 2 * pad);
    const y = H - pad - v * (H - 2 * pad - 12);
    pts.push(`${x.toFixed(1)},${y.toFixed(1)}`);
    if (h <= hNow) nowX = x;
  }
  const area = `${pad},${H - pad} ${pts.join(' ')} ${W - pad},${H - pad}`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="prod-curve" preserveAspectRatio="none" role="img" aria-label="Daily production curve">
      <defs>
        <linearGradient id="prodFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#ffb000" stopOpacity="0.45" />
          <stop offset="100%" stopColor="#ffb000" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map(g => (
        <line key={g} x1={pad} x2={W - pad} y1={pad + g * (H - 2 * pad)} y2={pad + g * (H - 2 * pad)} stroke="rgba(136,146,176,0.15)" strokeDasharray="4 4" />
      ))}
      <polygon points={area} fill="url(#prodFill)" />
      <polyline points={pts.join(' ')} fill="none" stroke="#ffb000" strokeWidth="2" />
      {hNow > SUNRISE_H && hNow < SUNSET_H && (
        <g>
          <line x1={nowX} x2={nowX} y1={pad} y2={H - pad} stroke="#ffbd59" strokeWidth="1.5" strokeDasharray="3 3" />
          <circle cx={nowX} cy={pad + 4} r="3" fill="#ffbd59" />
        </g>
      )}
    </svg>
  );
};

const SystemOverview: React.FC<SystemOverviewProps> = ({
  systemStatus,
  telemetryData,
  mqttConnected,
  now
}) => {
  const sceneNow = now || new Date();
  const [notifFeed, setNotifFeed] = useState<DashNotification[]>([]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const resp = await fetch('/api/notifications');
        if (!resp.ok) return;
        const data = await resp.json();
        if (!cancelled) setNotifFeed((data.notifications || []).slice(-4).reverse());
      } catch {
        /* non-fatal */
      }
    };
    void load();
    const iv = setInterval(load, 30000);
    return () => { cancelled = true; clearInterval(iv); };
  }, []);

  const halted = String(systemStatus?.status || '').toUpperCase() === 'HALTED';
  const latestTelemetry = telemetryData[telemetryData.length - 1];
  // Prefer the freshest 3-second telemetry sample for the live figures so the
  // numbers move with the chart instead of lagging behind the 30s status beacon.
  const currentPower = Number(
    latestTelemetry?.power_kw ?? latestTelemetry?.power ??
    systemStatus?.power_kw ?? systemStatus?.power ?? 0
  );
  const observedPeak = telemetryData.reduce(
    (m, d) => Math.max(m, Number(d.power_kw ?? d.power ?? d.value ?? 0)), 0
  );
  const peakKw = Math.max(observedPeak, currentPower, CAPACITY_KW * 0.85);

  const avgPower = telemetryData.length > 0
    ? telemetryData.reduce((sum, d) => sum + (Number(d.power_kw ?? d.power ?? d.value ?? 0)), 0) / telemetryData.length
    : 0;

  const irradiance = Math.round((currentPower / CAPACITY_KW) * 950); // W/m² estimate
  const ambient = 27;
  const panelTemp = halted ? ambient : Math.round(ambient + irradiance / 42);
  const performanceRatio = halted ? 0 : Math.min(99, Math.round((currentPower / (CAPACITY_KW * Math.max(0.08, elevationFactor(localHours(new Date()))))) * 92));
  const todayKwh = estimateTodayKwh(peakKw);
  const co2Kg = (todayKwh * GRID_CO2_FACTOR).toFixed(1);
  const revenueEur = (todayKwh * TARIFF_EUR).toFixed(2);
  const soc = halted ? batterySoc() : batterySoc();

  const capacityPct = Math.round((currentPower / CAPACITY_KW) * 100);
  const sunPct = (() => {
    const h = localHours(new Date());
    if (h <= SUNRISE_H) return 0;
    if (h >= SUNSET_H) return 100;
    return Math.round(((h - SUNRISE_H) / (SUNSET_H - SUNRISE_H)) * 100);
  })();

  const units = [
    { id: 'INV-01', name: 'Inverter A (SolarEdge SE7600H)', status: halted ? 'fault' : 'ok', value: `${currentPower.toFixed(2)} kW` },
    { id: 'STR-A', name: 'String A · 10× modules S-E', status: halted ? 'offline' : (sunPct === 0 ? 'idle' : 'ok'), value: halted ? '0.00 kW' : `${(currentPower * 0.52).toFixed(2)} kW` },
    { id: 'STR-B', name: 'String B · 10× modules S-W', status: halted ? 'offline' : (sunPct === 0 ? 'idle' : 'ok'), value: halted ? '0.00 kW' : `${(currentPower * 0.48).toFixed(2)} kW` },
    { id: 'BAT-01', name: 'Battery Bank · 9.7 kWh LFP', status: 'ok', value: `${soc}% SOC` },
    { id: 'MTR-01', name: 'Grid Export Meter', status: 'ok', value: halted ? 'import' : (currentPower > 1.8 ? 'exporting' : 'balanced') },
  ];

  return (
    <div className="system-overview">
      {halted && (
        <div className="halt-banner">
          ⛔ PLANT HALTED — Inverter output forced to 0 kW by remote command. Investigate Security Alerts immediately.
        </div>
      )}

      <div className="page-header">
        <h2>Plant Overview</h2>
        <p>Site CY-LIM-042 · Limassol · Real-time monitoring and control</p>
      </div>

      <div className="metrics-grid">
        <div className="metric-card metric-primary">
          <div className="metric-icon">☀️</div>
          <div className="metric-content">
            <div className="metric-label">Live AC Output</div>
            <div className="metric-value">{currentPower.toFixed(2)} <span className="metric-unit">kW</span></div>
            <div className="capacity-bar" title={`${capacityPct}% of ${CAPACITY_KW} kW rated`}>
              <div className={`capacity-fill ${halted ? 'halted' : ''}`} style={{ width: `${Math.min(100, capacityPct)}%` }} />
            </div>
            <div className="metric-info">{capacityPct}% of {(CAPACITY_KW).toFixed(1)} kW rated capacity</div>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon">🔋</div>
          <div className="metric-content">
            <div className="metric-label">Energy Today</div>
            <div className="metric-value">{todayKwh.toFixed(2)} <span className="metric-unit">kWh</span></div>
            <div className="metric-sub">€{revenueEur} earned · {co2Kg} kg CO₂ avoided</div>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon">📉</div>
          <div className="metric-content">
            <div className="metric-label">Performance Ratio</div>
            <div className="metric-value">{isFinite(performanceRatio) ? performanceRatio : '—'}<span className="metric-unit">%</span></div>
            <div className="metric-sub">{avgPower.toFixed(2)} kW session average · {telemetryData.length} samples</div>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon">🔌</div>
          <div className="metric-content">
            <div className="metric-label">Grid Connection</div>
            <div className={`metric-value ${halted ? 'status-warn' : 'status-connected'}`}>{halted ? 'STANDBY' : 'EXPORTING'}</div>
            <div className="metric-info">
              {(latestTelemetry?.voltage_v ?? systemStatus?.voltage_v ?? 240).toFixed?.(1) ?? '240'} V · {(latestTelemetry?.current_a ?? systemStatus?.current_a ?? 0).toFixed?.(1) ?? '0.0'} A · 50.0 Hz
            </div>
          </div>
        </div>
      </div>

      <SolarScene
        now={sceneNow}
        halted={halted}
        irradiance={irradiance}
        panelTemp={panelTemp}
        ambient={ambient}
        conditions={irradiance > 700 ? 'Clear sky' : irradiance > 250 ? 'Partly cloudy' : sunPct === 0 ? 'Night' : 'Overcast'}
      />

      <div className="overview-columns">
        <div className="info-panel">
          <h3>Daily Production Curve</h3>
          <PowerChartMini peakKw={peakKw} halted={halted} />
          <div className="curve-legend"><span>— projected output</span><span style={{ color: '#ffbd59' }}>— now</span></div>
        </div>
      </div>

      <div className="info-panels">
        <div className="info-panel">
          <h3>Plant Units</h3>
          <table className="units-table">
            <thead><tr><th>Unit</th><th>Description</th><th>Status</th><th>Reading</th></tr></thead>
            <tbody>
              {units.map(u => (
                <tr key={u.id}>
                  <td className="code">{u.id}</td>
                  <td>{u.name}</td>
                  <td><span className={`unit-dot unit-${u.status}`} /> {u.status.toUpperCase()}</td>
                  <td>{u.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="info-panel">
          <h3>System Information</h3>
          <div className="info-grid">
            <div className="info-row"><span className="info-key">Controller:</span><span className="info-value">SolarEdge SE7600H · fw 4.12.34</span></div>
            <div className="info-row"><span className="info-key">Commissioned:</span><span className="info-value">2024-03-15</span></div>
            <div className="info-row"><span className="info-key">Array:</span><span className="info-value">20 × 400 W bifacial</span></div>
            <div className="info-row"><span className="info-key">Telemetry:</span><span className="info-value">{mqttConnected ? 'MQTT live stream active' : 'waiting for data…'}</span></div>
            <div className="info-row"><span className="info-key">Session:</span><span className="info-value code">{systemStatus?.session || 'N/A'}</span></div>
          </div>
        </div>
      </div>

      <div className="alert-section">
        <h3>System Alerts &amp; Notifications</h3>
        <div className="alert-list">
          {notifFeed.length === 0 ? (
            <div className="alert alert-info">
              <span className="alert-icon">ℹ️</span>
              <div className="alert-content">
                <div className="alert-title">No recent notifications</div>
                <div className="alert-message">PV controller operating normally. All systems functional.</div>
                <div className="alert-time">just now</div>
              </div>
            </div>
          ) : notifFeed.map(n => (
            <div key={n.id} className={`alert ${n.read ? 'alert-info' : 'alert-warning'}`}>
              <span className="alert-icon">{n.read ? '✓' : '⚠️'}</span>
              <div className="alert-content">
                <div className="alert-title">{n.title}</div>
                <div className="alert-message">{n.message}</div>
                <div className="alert-time">{new Date(n.timestamp).toLocaleString()}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default SystemOverview;
