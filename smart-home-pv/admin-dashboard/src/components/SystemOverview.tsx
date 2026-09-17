import React, { useState, useEffect } from 'react';
import { MAP_SITES, siteById } from '../data/mapSites';
import { SiteLive } from './Dashboard';
import SecurityPosture from './SecurityPosture';
import './SystemOverview.css';

interface SystemOverviewProps {
  systemStatus: any;
  telemetryData: any[];
  mqttConnected: boolean;
  now?: Date;
  siteData?: Record<string, SiteLive>;
  token: string;
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
const STALE_AFTER_S = 30;

const localHours = (d: Date) => d.getHours() + d.getMinutes() / 60 + d.getSeconds() / 3600;

/** Same daylight model as the controller simulation - keeps numbers consistent */
const elevationFactor = (h: number) => {
  if (h <= SUNRISE_H || h >= SUNSET_H) return 0;
  const x = (h - SUNRISE_H) / (SUNSET_H - SUNRISE_H);
  return Math.max(0, Math.pow(Math.sin(Math.PI * x), 1.35));
};

/** Energy so far today (kWh) by integrating a kW-vs-hour profile */
const integrateToday = (profile: (h: number) => number) => {
  const h = localHours(new Date());
  let kwh = 0;
  const stepH = 0.25;
  for (let t = 0; t < Math.min(h, 24); t += stepH) {
    kwh += profile(t) * stepH;
  }
  return kwh;
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

const PowerChartMini: React.FC<{
  peakKw: number;
  halted: boolean;
  profile: (h: number) => number;
  fullDay?: boolean;
}> = ({ peakKw, halted, profile, fullDay }) => {
  // SVG sparkline of today's expected curve with a live "now" marker
  const W = 560;
  const H = 130;
  const pad = 6;
  const pts: string[] = [];
  const N = 64;
  const now = new Date();
  const hNow = localHours(now);
  const scale = Math.max(peakKw, 1);
  const h0 = fullDay ? 0 : SUNRISE_H;
  const h1 = fullDay ? 24 : SUNSET_H;
  let nowX = pad;
  for (let i = 0; i <= N; i++) {
    const frac = i / N;
    const h = h0 + frac * (h1 - h0);
    const v = halted ? 0 : Math.min(1, profile(h) / scale);
    const x = pad + frac * (W - 2 * pad);
    const y = H - pad - v * (H - 2 * pad - 12);
    pts.push(`${x.toFixed(1)},${y.toFixed(1)}`);
    if (h <= hNow) nowX = x;
  }
  const area = `${pad},${H - pad} ${pts.join(' ')} ${W - pad},${H - pad}`;
  const showNow = hNow > h0 && hNow < h1;
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
      {showNow && (
        <g>
          <line x1={nowX} x2={nowX} y1={pad} y2={H - pad} stroke="#ffbd59" strokeWidth="1.5" strokeDasharray="3 3" />
          <circle cx={nowX} cy={pad + 4} r="3" fill="#ffbd59" />
        </g>
      )}
    </svg>
  );
};

/* ------------------------------------------------------------------ */
/* Per-asset view model: same page structure, data scoped to an asset  */
/* ------------------------------------------------------------------ */
interface UnitRow { id: string; name: string; status: string; value: string; }
interface InfoRow { key: string; value: string; code?: boolean; }

interface AssetView {
  subtitle: string;
  consumer: boolean;
  capacityKw: number;
  currentPower: number;
  voltage: number;
  current: number;
  avgPower: number;
  samples: number;
  peakKw: number;
  halted: boolean;
  stale: boolean;
  statusWord: string;
  banner: string | null;
  powerLabel: string;
  ratioLabel: string;
  energySub: string;
  curveTitle: string;
  fullDayCurve: boolean;
  profile: (h: number) => number;
  units: UnitRow[];
  sysinfo: InfoRow[];
}

const SystemOverview: React.FC<SystemOverviewProps> = ({
  systemStatus,
  telemetryData,
  mqttConnected,
  now,
  siteData,
  token,
}) => {
  const sceneNow = now || new Date();
  const [notifFeed, setNotifFeed] = useState<DashNotification[]>([]);
  const [assetId, setAssetId] = useState('controller');
  const [section, setSection] = useState<'summary' | 'production' | 'equipment' | 'alerts'>('summary');

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

  const hNow = localHours(sceneNow);
  const sunPct = (() => {
    if (hNow <= SUNRISE_H) return 0;
    if (hNow >= SUNSET_H) return 100;
    return Math.round(((hNow - SUNRISE_H) / (SUNSET_H - SUNRISE_H)) * 100);
  })();

  /* ---- controller asset (the original Plant Overview content) ---- */
  const buildControllerView = (): AssetView => {
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
    const profile = (h: number) => peakKw * elevationFactor(h);
    const todayKwh = integrateToday(profile);
    const soc = batterySoc();
    return {
      subtitle: 'Site CY-LIM-042 · Limassol · Real-time monitoring and control',
      consumer: false,
      capacityKw: CAPACITY_KW,
      currentPower,
      voltage: Number(latestTelemetry?.voltage_v ?? systemStatus?.voltage_v ?? 240),
      current: Number(latestTelemetry?.current_a ?? systemStatus?.current_a ?? 0),
      avgPower,
      samples: telemetryData.length,
      peakKw,
      halted,
      stale: false,
      statusWord: halted ? 'STANDBY' : 'EXPORTING',
      banner: halted
        ? '⛔ PLANT HALTED — Inverter output forced to 0 kW by remote command. Investigate Security Alerts immediately.'
        : null,
      powerLabel: 'Live AC Output',
      ratioLabel: 'Performance Ratio',
      energySub: `€${(todayKwh * TARIFF_EUR).toFixed(2)} earned · ${(todayKwh * GRID_CO2_FACTOR).toFixed(1)} kg CO₂ avoided`,
      curveTitle: 'Daily Production Curve',
      fullDayCurve: false,
      profile,
      units: [
        { id: 'INV-01', name: 'Inverter A (SolarEdge SE7600H)', status: halted ? 'fault' : 'ok', value: `${currentPower.toFixed(2)} kW` },
        { id: 'STR-A', name: 'String A · 10× modules S-E', status: halted ? 'offline' : (sunPct === 0 ? 'idle' : 'ok'), value: halted ? '0.00 kW' : `${(currentPower * 0.52).toFixed(2)} kW` },
        { id: 'STR-B', name: 'String B · 10× modules S-W', status: halted ? 'offline' : (sunPct === 0 ? 'idle' : 'ok'), value: halted ? '0.00 kW' : `${(currentPower * 0.48).toFixed(2)} kW` },
        { id: 'BAT-01', name: 'Battery Bank · 9.7 kWh LFP', status: 'ok', value: `${soc}% SOC` },
        { id: 'MTR-01', name: 'Grid Export Meter', status: 'ok', value: halted ? 'import' : (currentPower > 1.8 ? 'exporting' : 'balanced') },
      ],
      sysinfo: [
        { key: 'Controller:', value: 'SolarEdge SE7600H · fw 4.12.34' },
        { key: 'Commissioned:', value: '2024-03-15' },
        { key: 'Array:', value: '20 × 400 W bifacial' },
        { key: 'Telemetry:', value: mqttConnected ? 'MQTT live stream active' : 'waiting for data…' },
        { key: 'Session:', value: systemStatus?.session || 'N/A', code: true },
      ],
    };
  };

  /* ---- map-site assets (houses / pv plant / army base) ----------- */
  const buildSiteView = (id: string): AssetView => {
    const meta = siteById(id)!;
    const live = siteData?.[id];
    const latest = live?.latest ?? null;
    const history = live?.history ?? [];
    const consumer = meta.type === 'army';
    const cap = (consumer ? meta.ratedLoadKw : meta.capacityKw) ?? 1;
    const stale = !latest || Date.now() / 1000 - Number(latest.ts ?? 0) > STALE_AFTER_S;
    const fault = latest?.status === 'fault';
    const mag = (t: any) => Math.abs(Number(t?.power_kw ?? t?.load_kw ?? 0));
    const currentPower = stale ? 0 : mag(latest);
    const observedPeak = history.reduce((m, d) => Math.max(m, mag(d)), 0);
    const peakKw = Math.max(observedPeak, currentPower, cap * (consumer ? 0.9 : 0.85));
    const avgPower = history.length > 0
      ? history.reduce((s, d) => s + mag(d), 0) / history.length
      : 0;
    const profile = consumer
      ? (h: number) => cap * (0.47 + 0.4 * (0.35 + 0.65 * elevationFactor(h)))
      : (h: number) => cap * elevationFactor(h) * 0.93;
    const todayKwh = integrateToday(profile);
    const soc = batterySoc();
    const idle = latest?.status === 'idle';
    const prodStatus = stale ? 'offline' : fault ? 'fault' : idle ? 'idle' : 'ok';
    const seeder = latest?.seeder;

    const units: UnitRow[] = meta.type === 'house' ? [
      { id: 'INV-01', name: `Inverter (${meta.model})`, status: prodStatus, value: `${currentPower.toFixed(2)} kW` },
      { id: 'STR-A', name: 'String A · roof half S-E', status: prodStatus, value: `${(currentPower * 0.52).toFixed(2)} kW` },
      { id: 'STR-B', name: 'String B · roof half S-W', status: prodStatus, value: `${(currentPower * 0.48).toFixed(2)} kW` },
      { id: 'BAT-01', name: `Battery Bank · ${(cap * 1.8).toFixed(1)} kWh LFP`, status: 'ok', value: `${soc}% SOC` },
      { id: 'MTR-01', name: 'Grid Export Meter', status: stale ? 'offline' : 'ok', value: stale ? 'no data' : (currentPower > cap * 0.3 ? 'exporting' : 'balanced') },
    ] : meta.type === 'plant' ? [
      { id: 'INV-C1', name: `Central Inverter (${meta.model.split(' · ')[0]})`, status: prodStatus, value: `${currentPower.toFixed(1)} kW` },
      { id: 'ARR-A', name: 'Array Field A · rows 1-3', status: prodStatus, value: `${(currentPower * 0.6).toFixed(1)} kW` },
      { id: 'ARR-B', name: 'Array Field B · rows 4-5', status: prodStatus, value: `${(currentPower * 0.4).toFixed(1)} kW` },
      { id: 'TX-01', name: 'Substation Transformer 11/0.4 kV', status: stale ? 'offline' : 'ok', value: `${Math.round(34 + (currentPower / cap) * 18)}°C oil` },
      { id: 'MTR-01', name: 'MV Export Meter', status: stale ? 'offline' : 'ok', value: stale ? 'no data' : (currentPower > 5 ? 'exporting' : 'balanced') },
    ] : [
      { id: 'SWB-01', name: 'Main LV Switchboard · 400 V', status: stale ? 'offline' : fault ? 'fault' : 'ok', value: `${currentPower.toFixed(1)} kW` },
      { id: 'UPS-01', name: 'UPS · 40 kVA double-conversion', status: 'ok', value: '100% SOC' },
      { id: 'GEN-01', name: 'Diesel Genset · 60 kVA backup', status: 'idle', value: 'standby' },
      { id: 'MTR-01', name: 'Feed Meter · from Substation TX-01', status: stale ? 'offline' : 'ok', value: stale ? 'no data' : 'importing' },
    ];

    return {
      subtitle: `${meta.name} · ${meta.feeder} · Real-time monitoring`,
      consumer,
      capacityKw: cap,
      currentPower,
      voltage: Number(latest?.voltage_v ?? (consumer ? 400 : 230)),
      current: Number(latest?.current_a ?? 0),
      avgPower,
      samples: history.length,
      peakKw,
      halted: fault,
      stale,
      statusWord: stale ? 'OFFLINE' : consumer ? 'IMPORTING' : fault ? 'STANDBY' : currentPower > 0.05 ? 'EXPORTING' : 'STANDBY',
      banner: stale
        ? `⚠️ NO TELEMETRY — the feeder container for ${meta.id} has not reported for over ${STALE_AFTER_S}s.`
        : fault ? `⛔ FAULT — ${meta.name} is reporting a fault condition.` : null,
      powerLabel: consumer ? 'Live Load' : 'Live AC Output',
      ratioLabel: consumer ? 'Load Factor' : 'Performance Ratio',
      energySub: consumer
        ? `€${(todayKwh * TARIFF_EUR).toFixed(2)} energy cost · ${(todayKwh * GRID_CO2_FACTOR).toFixed(1)} kg CO₂ grid mix`
        : `€${(todayKwh * TARIFF_EUR).toFixed(2)} earned · ${(todayKwh * GRID_CO2_FACTOR).toFixed(1)} kg CO₂ avoided`,
      curveTitle: consumer ? 'Daily Load Profile' : 'Daily Production Curve',
      fullDayCurve: consumer,
      profile,
      units,
      sysinfo: [
        { key: 'Equipment:', value: meta.model },
        { key: 'Commissioned:', value: meta.commissioned },
        { key: consumer ? 'Feed:' : 'Array:', value: meta.description },
        { key: 'Telemetry:', value: stale ? 'waiting for data…' : `MQTT live · ${seeder?.topic ?? `pv/telemetry/${meta.id}`}` },
        { key: 'Source:', value: seeder ? `${seeder.container} @ ${seeder.ip}` : 'N/A', code: true },
      ],
    };
  };

  const view = assetId === 'controller' ? buildControllerView() : buildSiteView(assetId);
  const capacityPct = Math.round((view.currentPower / view.capacityKw) * 100);
  const unreadCount = notifFeed.filter(n => !n.read).length;

  return (
    <div className="system-overview">
      <div className="page-header page-header-row">
        <div>
          <h2>Plant Overview</h2>
          <p>{view.subtitle}</p>
        </div>
        <label className="asset-select-label">
          <span>Asset</span>
          <select
            className="asset-select"
            value={assetId}
            onChange={e => setAssetId(e.target.value)}
            aria-label="Select asset to monitor"
          >
            <option value="controller">CY-LIM-042 · Plant Controller</option>
            <optgroup label="Area map assets">
              {MAP_SITES.map(s => (
                <option key={s.id} value={s.id}>
                  {s.name} · {s.type === 'house' ? 'House' : s.type === 'plant' ? 'PV Plant' : 'Army Base'}
                </option>
              ))}
            </optgroup>
          </select>
        </label>
      </div>

      <SecurityPosture token={token} systemStatus={systemStatus} siteData={siteData} />

      {view.banner && (
        <div className="halt-banner">{view.banner}</div>
      )}

      <nav className="ov-subtabs">
        {([
          ['summary', 'Summary'],
          ['production', 'Production'],
          ['equipment', 'Equipment'],
          ['alerts', 'Alerts'],
        ] as [typeof section, string][]).map(([key, label]) => (
          <button
            key={key}
            className={`ov-subtab ${section === key ? 'active' : ''}`}
            onClick={() => setSection(key)}
          >
            {label}
            {key === 'alerts' && unreadCount > 0 && <span className="ov-subtab-badge">{unreadCount}</span>}
          </button>
        ))}
      </nav>

      {section === 'summary' && (
        <div className="metrics-grid">
          <div className="metric-card metric-primary">
            <div className="metric-icon">{view.consumer ? '🏭' : '☀️'}</div>
            <div className="metric-content">
              <div className="metric-label">{view.powerLabel}</div>
              <div className="metric-value">{view.currentPower.toFixed(2)} <span className="metric-unit">kW</span></div>
              <div className="capacity-bar" title={`${capacityPct}% of ${view.capacityKw} kW rated`}>
                <div className={`capacity-fill ${view.halted || view.stale ? 'halted' : ''}`} style={{ width: `${Math.min(100, capacityPct)}%` }} />
              </div>
              <div className="metric-info">{capacityPct}% of {view.capacityKw.toFixed(1)} kW rated {view.consumer ? 'feed' : 'capacity'}</div>
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-icon">🔋</div>
            <div className="metric-content">
              <div className="metric-label">Energy Today</div>
              <div className="metric-value">{integrateToday(view.profile).toFixed(2)} <span className="metric-unit">kWh</span></div>
              <div className="metric-sub">{view.energySub}</div>
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-icon">📉</div>
            <div className="metric-content">
              <div className="metric-label">{view.ratioLabel}</div>
              <div className="metric-value">
                {view.consumer
                  ? Math.min(100, Math.round((view.avgPower / view.capacityKw) * 100))
                  : (view.halted || view.stale) ? 0
                  : Math.min(99, Math.round((view.currentPower / (view.capacityKw * Math.max(0.08, elevationFactor(hNow)))) * 92))}
                <span className="metric-unit">%</span>
              </div>
              <div className="metric-sub">{view.avgPower.toFixed(2)} kW session average · {view.samples} samples</div>
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-icon">🔌</div>
            <div className="metric-content">
              <div className="metric-label">Grid Connection</div>
              <div className={`metric-value ${view.halted || view.stale ? 'status-warn' : 'status-connected'}`}>{view.statusWord}</div>
              <div className="metric-info">
                {view.voltage.toFixed(1)} V · {view.current.toFixed(1)} A · 50.0 Hz
              </div>
            </div>
          </div>
        </div>
      )}

      {section === 'production' && (
        <div className="info-panels">
          <div className="info-panel info-panel-wide">
            <h3>{view.curveTitle}</h3>
            <PowerChartMini peakKw={view.peakKw} halted={view.halted} profile={view.profile} fullDay={view.fullDayCurve} />
            <div className="curve-legend"><span>— projected {view.consumer ? 'load' : 'output'}</span><span style={{ color: '#ffbd59' }}>— now</span></div>
          </div>
        </div>
      )}

      {section === 'equipment' && (
        <>
          <div className="info-panels">
            <div className="info-panel info-panel-wide">
              <h3>System Information</h3>
              <div className="info-grid">
                {view.sysinfo.map(row => (
                  <div className="info-row" key={row.key}>
                    <span className="info-key">{row.key}</span>
                    <span className={`info-value ${row.code ? 'code' : ''}`}>{row.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="info-panels">
            <div className="info-panel info-panel-wide">
              <h3>{view.consumer ? 'Installation Units' : 'Plant Units'}</h3>
              <table className="units-table">
                <thead><tr><th>Unit</th><th>Description</th><th>Status</th><th>Reading</th></tr></thead>
                <tbody>
                  {view.units.map(u => (
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
          </div>
        </>
      )}

      {section === 'alerts' && (
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
      )}
    </div>
  );
};

export default SystemOverview;
