import React, { useState, useEffect } from 'react';
import { MAP_SITES, SiteMeta } from '../data/mapSites';
import { SiteLive, SiteTelemetry } from './Dashboard';
import { logAdminActivity } from '../utils/activityLogger';
import './AreaMap.css';

interface AreaMapProps {
  siteData: Record<string, SiteLive>;
  token: string;
  mqttConnected: boolean;
  systemStatus?: { status?: string } | null;
}

/** The map site that represents the physical plant behind the Modbus controller. */
const CONTROLLER_SITE_ID = 'pv-plant';

const STALE_AFTER_S = 30;

const magnitudeKw = (t?: SiteTelemetry | null): number =>
  Math.abs(Number(t?.power_kw ?? t?.load_kw ?? 0));

const isStale = (t?: SiteTelemetry | null): boolean =>
  !t || Date.now() / 1000 - Number(t.ts ?? 0) > STALE_AFTER_S;

const fmtKw = (v: number) => `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} kW`;

const fmtUptime = (s?: number) => {
  if (s == null || !isFinite(s)) return '—';
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m ${Math.floor(s % 60)}s`;
};

const flowClass = (kw: number) =>
  kw < 0.1 ? 'flow-idle' : kw < 5 ? 'flow-low' : 'flow-high';

/** LED color class from payload status + staleness */
const ledClass = (t?: SiteTelemetry | null): string => {
  if (isStale(t)) return 'led-stale';
  switch (t?.status) {
    case 'fault': return 'led-crit';
    case 'idle': return 'led-idle';
    default: return 'led-ok';
  }
};

/* ------------------------------------------------------------------ */
/* Sparkline — same visual language as PowerChartMini in SystemOverview */
/* ------------------------------------------------------------------ */
const Sparkline: React.FC<{ history: SiteTelemetry[]; color: string; id: string }> = ({
  history, color, id,
}) => {
  const W = 280;
  const H = 64;
  const pad = 4;
  const values = history.map(magnitudeKw);
  if (values.length < 2) {
    return <div className="sparkline-empty">Awaiting samples…</div>;
  }
  const max = Math.max(...values, 0.1);
  const pts = values.map((v, i) => {
    const x = pad + (i / (values.length - 1)) * (W - 2 * pad);
    const y = H - pad - (v / max) * (H - 2 * pad - 6);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const area = `${pad},${H - pad} ${pts.join(' ')} ${W - pad},${H - pad}`;
  const gradId = `spark-${id}`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="site-sparkline" preserveAspectRatio="none"
         role="img" aria-label="Recent power history">
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.4" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {[0.5].map(g => (
        <line key={g} x1={pad} x2={W - pad} y1={pad + g * (H - 2 * pad)} y2={pad + g * (H - 2 * pad)}
              stroke="rgba(136,146,176,0.15)" strokeDasharray="4 4" />
      ))}
      <polygon points={area} fill={`url(#${gradId})`} />
      <polyline points={pts.join(' ')} fill="none" stroke={color} strokeWidth="1.8" />
    </svg>
  );
};

/* ------------------------------------------------------------------ */
/* Scenery helpers (top view, light from the north-west)               */
/* ------------------------------------------------------------------ */
const Tree: React.FC<{ x: number; y: number; r?: number }> = ({ x, y, r = 13 }) => (
  <g transform={`translate(${x}, ${y})`} className="tree" aria-hidden="true">
    <ellipse className="tree-shadow" cx={r * 0.35} cy={r * 0.4} rx={r} ry={r * 0.85} />
    <circle className="tree-crown" r={r} />
    <circle className="tree-crown-hi" cx={-r * 0.3} cy={-r * 0.3} r={r * 0.5} />
  </g>
);

const Car: React.FC<{ x: number; y: number; body?: string }> = ({ x, y, body = '#5a6f82' }) => (
  <g transform={`translate(${x}, ${y})`} className="car" aria-hidden="true">
    <rect x={-6} y={-13} width={12} height={26} rx={3} fill={body} stroke="rgba(0,0,0,0.4)" strokeWidth={0.8} />
    <rect x={-4.5} y={-7} width={9} height={6} rx={1} fill="rgba(16,20,24,0.55)" />
    <rect x={-4.5} y={4} width={9} height={5} rx={1} fill="rgba(16,20,24,0.4)" />
  </g>
);

const Truck: React.FC<{ x: number; y: number }> = ({ x, y }) => (
  <g transform={`translate(${x}, ${y})`} className="truck" aria-hidden="true">
    <rect className="truck-bed" x={-7} y={-14} width={14} height={20} rx={1.5} />
    <rect className="truck-cab" x={-6} y={7} width={12} height={8} rx={1.5} />
    <line x1={-7} y1={-9} x2={7} y2={-9} className="truck-rib" />
    <line x1={-7} y1={-3} x2={7} y2={-3} className="truck-rib" />
    <line x1={-7} y1={2} x2={7} y2={2} className="truck-rib" />
  </g>
);

/* ------------------------------------------------------------------ */
/* Map glyph shapes (top view), drawn centered on (0,0)                */
/* ------------------------------------------------------------------ */
const HouseShape: React.FC<{ producing: boolean; variant: number }> = ({ producing, variant }) => (
  <g>
    {/* yard */}
    <rect className="plot" x={-78} y={-60} width={156} height={128} rx={5} />
    <rect className="plot-fence" x={-78} y={-60} width={156} height={128} rx={5} />
    {/* driveway down to the road */}
    <rect className="driveway" x={22} y={64} width={20} height={68} />
    {/* garden path to the door */}
    <rect className="garden-path" x={26} y={38} width={8} height={28} />
    {/* the building: gabled roof seen from above, ridge running E-W */}
    <g className="building">
      <rect className="roof-n" x={-52} y={-40} width={104} height={40} />
      <rect className="roof-s" x={-52} y={0} width={104} height={40} />
      <line className="roof-ridge" x1={-52} y1={0} x2={52} y2={0} />
      <line className="roof-hip" x1={-52} y1={-40} x2={-44} y2={0} />
      <line className="roof-hip" x1={52} y1={-40} x2={44} y2={0} />
      <rect className="chimney" x={30} y={-30} width={9} height={9} />
    </g>
    {/* rooftop PV array on the south-facing half */}
    {[0, 1].map(r =>
      [0, 1, 2].map(c => (
        <rect key={`${r}-${c}`} className={`pv-panel ${producing ? 'pv-live' : ''}`}
              x={-42 + c * 29} y={5 + r * 16} width={25} height={12} rx={1} />
      ))
    )}
    {/* per-house yard details */}
    {variant === 0 && <Tree x={-56} y={44} r={12} />}
    {variant === 1 && <Car x={32} y={102} body="#7a4a3a" />}
    {variant === 2 && (
      <g className="pool" aria-hidden="true">
        <rect x={-66} y={30} width={34} height={24} rx={7} />
        <rect className="pool-water" x={-63} y={33} width={28} height={18} rx={5} />
      </g>
    )}
  </g>
);

const PlantShape: React.FC<{ producing: boolean }> = ({ producing }) => (
  <g>
    {/* gravel pad + perimeter fence */}
    <rect className="gravel-pad" x={-100} y={-70} width={200} height={140} rx={4} />
    <rect className="compound-fence" x={-100} y={-70} width={200} height={140} rx={4} />
    {[[-100, -70], [100, -70], [-100, 70], [100, 70]].map(([px, py], i) => (
      <rect key={i} className="fence-post" x={px - 3} y={py - 3} width={6} height={6} />
    ))}
    {/* gate towards the access road (south fence) */}
    <rect className="gate" x={-58} y={66} width={22} height={8} />
    {/* panel rows on racking, with maintenance walkways between */}
    {[0, 1, 2, 3, 4].map(r => (
      <g key={r} className="panel-row-g">
        <rect className="panel-row-shadow" x={-86} y={-56 + r * 23 + 3} width={132} height={12} rx={1} />
        <rect className={`panel-row ${producing ? 'pv-live' : ''}`}
              x={-88} y={-56 + r * 23} width={132} height={12} rx={1} fill="url(#panelCells)" />
      </g>
    ))}
    {/* substation / inverter hut TX-01 */}
    <g className="building">
      <rect className="hut-roof-n" x={54} y={-26} width={42} height={25} />
      <rect className="hut-roof-s" x={54} y={-1} width={42} height={25} />
      <line className="roof-ridge" x1={54} y1={-1} x2={96} y2={-1} />
    </g>
    {/* transformer yard beside the hut */}
    <circle className="tx-symbol" cx={66} cy={40} r={8} />
    <circle className="tx-symbol" cx={78} cy={40} r={8} />
    <rect className="tx-pad" x={54} y={28} width={38} height={24} rx={2} />
    <text className="micro-label" x={75} y={62} textAnchor="middle">TX-01</text>
    <Car x={-64} y={56} body="#5f6a72" />
  </g>
);

const ArmyShape: React.FC = () => (
  <g>
    {/* packed-earth compound + double fence */}
    <rect className="dirt-pad" x={-100} y={-70} width={200} height={140} rx={4} />
    <rect className="compound-fence army-fence" x={-100} y={-70} width={200} height={140} rx={4} />
    <rect className="army-fence-inner" x={-95} y={-65} width={190} height={130} rx={3} />
    {/* watchtowers on the corners */}
    {[[-96, -66], [96, -66], [-96, 66], [96, 66]].map(([px, py], i) => (
      <rect key={i} className="watchtower" x={px - 5} y={py - 5} width={10} height={10} />
    ))}
    {/* gate towards the road (north fence) */}
    <rect className="gate" x={8} y={-74} width={22} height={8} />
    {/* barracks with gabled roofs */}
    {[0, 1].map(i => (
      <g key={i} className="building">
        <rect className="barracks-roof-n" x={-86} y={-56 + i * 34} width={76} height={12} />
        <rect className="barracks-roof-s" x={-86} y={-44 + i * 34} width={76} height={12} />
        <line className="roof-ridge" x1={-86} y1={-44 + i * 34} x2={-10} y2={-44 + i * 34} />
      </g>
    ))}
    {/* tents */}
    {[0, 1].map(i => (
      <g key={i} className="tent-g">
        <rect className="tent" x={-84 + i * 40} y={16} width={30} height={22} rx={8} />
        <line className="tent-ridge" x1={-84 + i * 40 + 4} y1={27} x2={-84 + i * 40 + 26} y2={27} />
      </g>
    ))}
    {/* vehicle park */}
    <Truck x={14} y={-40} />
    <Truck x={34} y={-40} />
    <Truck x={14} y={24} />
    {/* helipad */}
    <circle className="helipad" cx={62} cy={28} r={21} />
    <circle className="helipad-inner" cx={62} cy={28} r={15} />
    <text className="helipad-h" x={62} y={34} textAnchor="middle">H</text>
    {/* flag */}
    <line className="flagpole" x1={80} y1={-58} x2={80} y2={-24} />
    <polygon className="flag" points="80,-58 96,-52 80,-46" />
    <text className="micro-label restricted" x={-40} y={54} textAnchor="middle">RESTRICTED AREA</text>
  </g>
);

interface GlyphProps {
  meta: SiteMeta;
  live?: SiteLive;
  selected: boolean;
  halted?: boolean;
  onSelect: (id: string) => void;
}

const SiteGlyph: React.FC<GlyphProps> = ({ meta, live, selected, halted, onSelect }) => {
  const latest = live?.latest;
  const stale = isStale(latest);
  const kw = magnitudeKw(latest);
  const consumer = meta.type === 'army';
  const producing = !halted && !stale && !consumer && kw > 0.05;
  const labelY = meta.type === 'house' ? -84 : -106;
  const badgeText = halted ? '⛔ HALTED' : stale ? '—' : consumer ? `▼ ${fmtKw(kw)}` : fmtKw(kw);
  const led = halted ? 'led-crit' : ledClass(latest);
  const variant = meta.type === 'house' ? Math.max(0, (parseInt(meta.id.split('-')[1] || '1', 10) - 1) % 3) : 0;

  const handleActivate = () => onSelect(meta.id);
  return (
    <g
      className={`map-site ${selected ? 'selected' : ''}`}
      transform={`translate(${meta.x}, ${meta.y})`}
      role="button"
      tabIndex={0}
      aria-label={`${meta.name} — ${badgeText}`}
      onClick={handleActivate}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleActivate(); } }}
    >
      {meta.type === 'house' && <HouseShape producing={producing} variant={variant} />}
      {meta.type === 'plant' && <PlantShape producing={producing} />}
      {meta.type === 'army' && <ArmyShape />}

      <text className="site-name" x={0} y={labelY} textAnchor="middle">{meta.name}</text>
      <g className="kw-badge">
        <rect x={-52} y={labelY + 6} width={104} height={20} rx={4} />
        <text x={4} y={labelY + 20} textAnchor="middle">{badgeText}</text>
        <circle className={`status-led ${led}`} cx={-40} cy={labelY + 16} r={4} />
      </g>
      {selected && (
        <rect className="selection-ring"
              x={meta.type === 'house' ? -84 : -108}
              y={meta.type === 'house' ? -66 : -78}
              width={meta.type === 'house' ? 168 : 216}
              height={meta.type === 'house' ? 140 : 156}
              rx={7} />
      )}
    </g>
  );
};

/* ------------------------------------------------------------------ */
/* Detail panel                                                        */
/* ------------------------------------------------------------------ */
const SiteDetailPanel: React.FC<{
  meta: SiteMeta;
  live?: SiteLive;
  plantLive?: SiteLive;
  halted?: boolean;
}> = ({ meta, live, plantLive, halted }) => {
  const latest = live?.latest ?? null;
  const history = live?.history ?? [];
  const stale = isStale(latest);
  const consumer = meta.type === 'army';
  const kw = magnitudeKw(latest);
  const ageS = latest?.ts ? Math.max(0, Math.round(Date.now() / 1000 - latest.ts)) : null;
  const statusText = halted ? 'HALTED' : !latest ? 'NO DATA' : stale ? 'STALE' : (latest.status || 'ok').toUpperCase();
  const statusClass = halted ? 'pill-crit'
    : !latest || stale ? 'pill-stale'
    : latest.status === 'fault' ? 'pill-crit'
    : latest.status === 'idle' ? 'pill-idle' : 'pill-ok';
  const sparkColor = consumer ? '#4aa3ff' : '#ffb000';
  // Flavor metric: how much of the base's draw the plant currently covers
  const plantKw = magnitudeKw(plantLive?.latest);
  const coverage = consumer && kw > 0 ? Math.min(100, Math.round(Math.min(plantKw, kw) / kw * 100)) : null;

  const typeLabel = meta.type === 'house' ? 'RESIDENTIAL INVERTER'
    : meta.type === 'plant' ? 'PLANT / SUBSTATION' : 'CONSUMER · MILITARY';

  return (
    <div className="site-detail-panel">
      <div className="detail-header">
        <div>
          <h3>{meta.name}</h3>
          <div className="detail-tags">
            <span className="site-id-chip">{meta.id}</span>
            <span className={`type-tag type-${meta.type}`}>{typeLabel}</span>
          </div>
        </div>
        <span className={`status-pill ${statusClass}`}>{statusText}</span>
      </div>

      <div className="live-readings">
        <div className="reading">
          <span className="reading-label">{consumer ? 'Load' : 'Power'}</span>
          <span className="reading-value">{latest ? `${consumer ? '▼ ' : ''}${fmtKw(kw)}` : '—'}</span>
        </div>
        <div className="reading">
          <span className="reading-label">Voltage</span>
          <span className="reading-value">{latest?.voltage_v != null ? `${latest.voltage_v.toFixed(1)} V` : '—'}</span>
        </div>
        <div className="reading">
          <span className="reading-label">Current</span>
          <span className="reading-value">{latest?.current_a != null ? `${latest.current_a.toFixed(1)} A` : '—'}</span>
        </div>
        {coverage != null && (
          <div className="reading">
            <span className="reading-label">PV coverage</span>
            <span className="reading-value">{coverage}%</span>
          </div>
        )}
      </div>
      <div className="reading-age">{ageS != null ? `updated ${ageS}s ago` : 'no telemetry received'}</div>

      <div className="detail-section">
        <h4>{consumer ? 'Load history' : 'Production history'}</h4>
        <Sparkline history={history} color={sparkColor} id={meta.id} />
      </div>

      <div className="detail-section">
        <h4>Telemetry source</h4>
        {latest?.seeder ? (
          <table className="spec-table">
            <tbody>
              <tr>
                <td>Container</td>
                <td>
                  <span className="feeder-led" />
                  {latest.seeder.container ?? '—'}
                </td>
              </tr>
              <tr><td>Address</td><td>{latest.seeder.ip ?? '—'}</td></tr>
              <tr><td>Topic</td><td>{latest.seeder.topic ?? `pv/telemetry/${meta.id}`}</td></tr>
              <tr>
                <td>Interval</td>
                <td>{latest.seeder.interval_s != null ? `every ${latest.seeder.interval_s}s` : '—'}</td>
              </tr>
              <tr>
                <td>Messages</td>
                <td>{latest.seeder.seq != null ? `#${latest.seeder.seq}` : '—'}</td>
              </tr>
              <tr><td>Feeder uptime</td><td>{fmtUptime(latest.seeder.uptime_s)}</td></tr>
            </tbody>
          </table>
        ) : (
          <p className="site-description">No feeder metadata in the last payload — the dedicated feeder container for this site is not reporting.</p>
        )}
      </div>

      <div className="detail-section">
        <h4>Equipment</h4>
        <table className="spec-table">
          <tbody>
            <tr><td>Model</td><td>{meta.model}</td></tr>
            <tr>
              <td>{consumer ? 'Rated load' : 'Capacity'}</td>
              <td>{consumer ? `${meta.ratedLoadKw} kW` : `${meta.capacityKw} kWp`}</td>
            </tr>
            <tr><td>Serial</td><td>{meta.serial}</td></tr>
            <tr><td>Commissioned</td><td>{meta.commissioned}</td></tr>
            <tr><td>Feeder</td><td>{meta.feeder}</td></tr>
          </tbody>
        </table>
        <p className="site-description">{meta.description}</p>
      </div>
    </div>
  );
};

/* ------------------------------------------------------------------ */
/* Main component                                                      */
/* ------------------------------------------------------------------ */
const AreaMap: React.FC<AreaMapProps> = ({ siteData, token, mqttConnected, systemStatus }) => {
  const [selectedId, setSelectedId] = useState('pv-plant');
  const selectedMeta = MAP_SITES.find(s => s.id === selectedId) || MAP_SITES[0];

  // Per-asset HALT state from the Modbus units (one unit per asset). Each asset
  // can be halted independently, so the map reflects exactly which ones are down.
  const [assetHalt, setAssetHalt] = useState<Record<string, boolean>>({});
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const resp = await fetch('/api/assets/status');
        if (!resp.ok) return;
        const data = await resp.json();
        const map: Record<string, boolean> = {};
        Object.entries(data.assets || {}).forEach(([id, v]: [string, any]) => {
          map[id] = !!v.halted;
        });
        if (!cancelled) setAssetHalt(map);
      } catch {
        /* non-fatal */
      }
    };
    void load();
    const iv = setInterval(load, 4000);
    return () => { cancelled = true; clearInterval(iv); };
  }, []);

  // Fallback: the controller's own status feed also marks the pv-plant halted.
  const controllerHalted = String(systemStatus?.status || '').toUpperCase() === 'HALTED';
  const isHalted = (id: string) =>
    !!assetHalt[id] || (id === CONTROLLER_SITE_ID && controllerHalted);

  const handleSelect = (id: string) => {
    setSelectedId(id);
    void logAdminActivity({
      action: 'map_site_selected',
      eventType: 'navigation',
      page: 'dashboard/areamap',
      target: id,
      details: { site: id },
    }, token);
  };

  const houseFeeders = MAP_SITES.filter(s => s.type === 'house');
  const plant = MAP_SITES.find(s => s.id === 'pv-plant')!;
  const army = MAP_SITES.find(s => s.id === 'army-base')!;

  // District-level aggregates from the freshest per-site samples
  const fresh = MAP_SITES.map(s => ({ meta: s, latest: siteData[s.id]?.latest }))
    .filter(e => !isStale(e.latest));
  const totalGenKw = fresh
    .filter(e => e.meta.type !== 'army')
    .reduce((sum, e) => sum + magnitudeKw(e.latest), 0);
  const totalLoadKw = fresh
    .filter(e => e.meta.type === 'army')
    .reduce((sum, e) => sum + magnitudeKw(e.latest), 0);
  const netKw = totalGenKw - totalLoadKw;

  return (
    <div className="area-map-page">
      <div className="page-header">
        <h2>Area Map</h2>
        <p className="page-subtitle">
          Neighborhood feeder · Ktima Elia district · live per-site telemetry
          {!mqttConnected && <span className="link-warning"> · TELEMETRY LINK DOWN</span>}
        </p>
      </div>

      <div className="map-kpis" role="group" aria-label="District totals">
        <div className="map-kpi">
          <span className="map-kpi-label">Generation</span>
          <span className="map-kpi-value">{fmtKw(totalGenKw)}</span>
        </div>
        <div className="map-kpi">
          <span className="map-kpi-label">Load</span>
          <span className="map-kpi-value kpi-load">▼ {fmtKw(totalLoadKw)}</span>
        </div>
        <div className="map-kpi">
          <span className="map-kpi-label">Net to grid</span>
          <span className={`map-kpi-value ${netKw >= 0 ? 'kpi-net-pos' : 'kpi-net-neg'}`}>
            {netKw >= 0 ? '+' : ''}{fmtKw(netKw)}
          </span>
        </div>
        <div className="map-kpi">
          <span className="map-kpi-label">Sites online</span>
          <span className="map-kpi-value">{fresh.length} / {MAP_SITES.length}</span>
        </div>
      </div>

      <div className="area-map-layout">
        <div className="map-panel">
          <div className="map-toolbar" role="tablist" aria-label="Select a site">
            {MAP_SITES.map(s => (
              <button
                key={s.id}
                role="tab"
                aria-selected={selectedId === s.id}
                className={`site-chip ${selectedId === s.id ? 'active' : ''}`}
                onClick={() => handleSelect(s.id)}
              >
                <span className={`status-led-dot ${ledClass(siteData[s.id]?.latest)}`} />
                {s.name}
              </button>
            ))}
          </div>
          <svg viewBox="0 0 1000 620" preserveAspectRatio="xMidYMid meet"
               className="area-map-svg" aria-label="Area map">
            <defs>
              {/* individual PV modules inside a plant panel row */}
              <pattern id="panelCells" width="9" height="13" patternUnits="userSpaceOnUse">
                <rect width="9" height="13" fill="#152436" />
                <rect x="0.7" y="0.7" width="7.6" height="11.6" fill="#1d3a57" />
              </pattern>
              {/* crop rows in the fields */}
              <pattern id="fieldRows" width="12" height="12" patternUnits="userSpaceOnUse"
                       patternTransform="rotate(90)">
                <rect width="12" height="12" fill="transparent" />
                <line x1="0" y1="2" x2="12" y2="2" stroke="rgba(0,0,0,0.22)" strokeWidth="3" />
              </pattern>
              {/* soft drop shadow for buildings, light from the NW */}
              <filter id="bldShadow" x="-30%" y="-30%" width="160%" height="160%">
                <feDropShadow dx="4" dy="5" stdDeviation="3" floodColor="#000" floodOpacity="0.35" />
              </filter>
            </defs>

            {/* --- terrain --- */}
            <g className="terrain" aria-hidden="true">
              <rect className="ground" x={0} y={0} width={1000} height={620} />
              {/* cultivated fields, south-west */}
              <rect className="field field-a" x={16} y={348} width={264} height={104} rx={3} />
              <rect className="field field-a" x={16} y={348} width={264} height={104} rx={3} fill="url(#fieldRows)" />
              <rect className="field field-b" x={16} y={464} width={264} height={128} rx={3} />
              <rect className="field field-b" x={16} y={464} width={264} height={128} rx={3} fill="url(#fieldRows)" />
              {/* pond */}
              <path className="water" d="M 392 520
                    C 372 498 392 474 428 476
                    C 470 470 502 486 498 512
                    C 494 540 458 552 428 546
                    C 408 542 400 534 392 520 Z" />
              {/* roads */}
              <rect className="road-shoulder" x={0} y={274} width={1000} height={52} />
              <rect className="road" x={0} y={278} width={1000} height={44} />
              <line className="road-edge" x1={0} y1={282} x2={1000} y2={282} />
              <line className="road-edge" x1={0} y1={318} x2={1000} y2={318} />
              <line className="road-centerline" x1={0} y1={300} x2={1000} y2={300} />
              {/* access roads: plant (north) and army gate (south) */}
              <rect className="road access-road" x={702} y={188} width={22} height={92} />
              <rect className="road access-road" x={766} y={320} width={22} height={42} />
              {/* trees */}
              <Tree x={60} y={72} />
              <Tree x={238} y={58} r={11} />
              <Tree x={437} y={84} r={15} />
              <Tree x={610} y={66} r={11} />
              <Tree x={86} y={246} r={12} />
              <Tree x={282} y={244} r={10} />
              <Tree x={475} y={248} r={13} />
              <Tree x={330} y={470} r={14} />
              <Tree x={358} y={568} r={10} />
              <Tree x={545} y={500} r={12} />
              <Tree x={618} y={420} r={13} />
              <Tree x={920} y={238} r={14} />
              <Tree x={946} y={560} r={12} />
              <Tree x={660} y={584} r={10} />
              {/* compass + scale */}
              <g className="chart-plate" transform="translate(948, 62)">
                <circle r={18} className="compass-ring" />
                <polygon points="0,-13 4,4 0,1 -4,4" className="compass-needle" />
                <text y={32} textAnchor="middle" className="micro-label">N</text>
              </g>
              <g className="chart-plate" transform="translate(830, 602)">
                <line x1={0} y1={0} x2={100} y2={0} className="scale-bar" />
                <line x1={0} y1={-4} x2={0} y2={4} className="scale-bar" />
                <line x1={100} y1={-4} x2={100} y2={4} className="scale-bar" />
                <text x={50} y={-6} textAnchor="middle" className="micro-label">100 m</text>
              </g>
            </g>

            {/* --- feeder lines --- */}
            <g className="feeders">
              {houseFeeders.map(h => (
                <line key={h.id}
                      className={`feeder ${flowClass(magnitudeKw(siteData[h.id]?.latest))}`}
                      x1={h.x} y1={h.y + 40} x2={h.x} y2={282} />
              ))}
              {/* plant to road */}
              <line className={`feeder feeder-heavy ${flowClass(magnitudeKw(siteData['pv-plant']?.latest))}`}
                    x1={plant.x - 68} y1={plant.y + 70} x2={plant.x - 68} y2={282} />
              {/* plant feeds the army base across the road */}
              <line className={`feeder feeder-heavy ${flowClass(magnitudeKw(siteData['army-base']?.latest))}`}
                    x1={plant.x + 46} y1={plant.y + 70} x2={army.x + 46} y2={army.y - 70} />
            </g>

            {/* --- sites --- */}
            <g className="sites">
              {MAP_SITES.map(meta => (
                <SiteGlyph key={meta.id}
                           meta={meta}
                           live={siteData[meta.id]}
                           selected={selectedId === meta.id}
                           halted={isHalted(meta.id)}
                           onSelect={handleSelect} />
              ))}
            </g>
          </svg>

          <div className="map-legend" aria-label="Map legend">
            <span className="legend-item"><span className="status-led-dot led-ok" /> producing / ok</span>
            <span className="legend-item"><span className="status-led-dot led-idle" /> idle (night)</span>
            <span className="legend-item"><span className="status-led-dot led-crit" /> fault</span>
            <span className="legend-item"><span className="status-led-dot led-stale" /> no data</span>
            <span className="legend-item"><span className="legend-line legend-flow" /> power flow</span>
            <span className="legend-item"><span className="legend-arrow">▼</span> consumption</span>
          </div>
        </div>

        <SiteDetailPanel meta={selectedMeta}
                         live={siteData[selectedId]}
                         plantLive={siteData['pv-plant']}
                         halted={isHalted(selectedId)} />
      </div>
    </div>
  );
};

export default AreaMap;
