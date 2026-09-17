import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { MAP_SITES } from '../data/mapSites';
import { SiteLive } from './Dashboard';
import './SecurityPosture.css';

interface SecurityPostureProps {
  token: string;
  systemStatus: any;
  siteData?: Record<string, SiteLive>;
}

interface SecEvent {
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  category: string;
  message: string;
  details?: string;
  source?: string;
  ip?: string;
}

type Vector = 'web' | 'mqtt' | 'modbus';

const STALE_AFTER_S = 30;

/* Map the backend's event categories onto the three attack surfaces of the
 * exercise: the web admin panel (brute force / phishing / injection), the MQTT
 * telemetry-and-control channel, and the Modbus/TCP ICS interface. */
const CATEGORY_VECTOR: Record<string, Vector> = {
  Authentication: 'web',
  'Rate Limiting': 'web',
  'Web Application Security': 'web',
  Phishing: 'web',
  'Network Access': 'web',
  'System Control': 'mqtt',
  'Data Integrity': 'mqtt',
  'ICS Protocol': 'modbus',
};

const vectorOf = (ev: SecEvent): Vector | null => {
  if (ev.category && CATEGORY_VECTOR[ev.category]) return CATEGORY_VECTOR[ev.category];
  const src = (ev.source || '').toLowerCase();
  if (src.includes('modbus')) return 'modbus';
  if (src.includes('mqtt')) return 'mqtt';
  if (src.includes('auth') || src.includes('phish') || src.includes('login')) return 'web';
  return null;
};

const SEV_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/* posture rank: -1 secure, 0/1 guarded, 2 elevated, 3 critical */
const rankToLevel = (rank: number): { key: string; label: string } => {
  if (rank >= 3) return { key: 'critical', label: 'CRITICAL' };
  if (rank === 2) return { key: 'elevated', label: 'ELEVATED' };
  if (rank >= 0) return { key: 'guarded', label: 'GUARDED' };
  return { key: 'secure', label: 'SECURE' };
};

const relTime = (iso?: string): string => {
  if (!iso) return 'never';
  const t = new Date(iso).getTime();
  if (isNaN(t)) return 'never';
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};

const isStale = (live?: SiteLive): boolean => {
  const ts = live?.latest?.ts;
  return ts == null || Date.now() / 1000 - Number(ts) > STALE_AFTER_S;
};

const VECTOR_META: Record<Vector, { title: string; sub: string; icon: string }> = {
  web: { title: 'Web / Admin Panel', sub: 'Brute force · phishing · injection', icon: '🌐' },
  mqtt: { title: 'MQTT Telemetry', sub: 'Control channel · data integrity', icon: '📡' },
  modbus: { title: 'Modbus / ICS', sub: 'TX-01 field interface · coil writes', icon: '🏭' },
};

const SecurityPosture: React.FC<SecurityPostureProps> = ({ token, systemStatus, siteData }) => {
  const [events, setEvents] = useState<SecEvent[]>([]);
  const [blockedCount, setBlockedCount] = useState(0);
  const [monitorOnline, setMonitorOnline] = useState(true);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const resp = await axios.get('/api/admin/security/events', {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (alive) {
          setEvents(Array.isArray(resp.data?.events) ? resp.data.events : []);
          setMonitorOnline(true);
        }
      } catch {
        if (alive) setMonitorOnline(false);
      }
    };
    void load();
    const iv = setInterval(load, 8000);
    return () => { alive = false; clearInterval(iv); };
  }, [token]);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const resp = await axios.get('/api/admin/security/blocked', {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (alive) setBlockedCount(Object.keys(resp.data?.blocked_ips || {}).length);
      } catch {
        /* non-fatal */
      }
    };
    void load();
    const iv = setInterval(load, 20000);
    return () => { alive = false; clearInterval(iv); };
  }, [token]);

  const halted = String(systemStatus?.status || '').toUpperCase() === 'HALTED';

  /* ---- aggregate per vector ---- */
  const byVector: Record<Vector, SecEvent[]> = { web: [], mqtt: [], modbus: [] };
  for (const ev of events) {
    const v = vectorOf(ev);
    if (v) byVector[v].push(ev);
  }

  const vectorStat = (v: Vector) => {
    const list = byVector[v];
    const critical = list.filter(e => e.severity === 'critical').length;
    const high = list.filter(e => e.severity === 'high').length;
    let rank = -1;
    let last: SecEvent | undefined;
    for (const e of list) {
      rank = Math.max(rank, SEV_RANK[e.severity] ?? 0);
      if (!last || new Date(e.timestamp) > new Date(last.timestamp)) last = e;
    }
    // Modbus/ICS or MQTT-driven HALT is a live compromise, force critical.
    if (v !== 'web' && halted) rank = Math.max(rank, 3);
    return { total: list.length, critical, high, rank, last, level: rankToLevel(rank) };
  };

  const vectors: Vector[] = ['web', 'mqtt', 'modbus'];
  const vstats = Object.fromEntries(vectors.map(v => [v, vectorStat(v)])) as Record<
    Vector, ReturnType<typeof vectorStat>
  >;

  const totalCritical = events.filter(e => e.severity === 'critical').length;
  const totalHigh = events.filter(e => e.severity === 'high').length;
  const last24h = events.filter(
    e => Date.now() - new Date(e.timestamp).getTime() < 24 * 3600 * 1000
  ).length;

  const overallRank = Math.max(
    halted ? 3 : -1,
    ...vectors.map(v => vstats[v].rank)
  );
  const overall = rankToLevel(overallRank);

  /* ---- per-asset posture ---- */
  const assetExposure: Record<string, Vector[]> = {
    'pv-plant': ['web', 'mqtt', 'modbus'],
    'house-1': ['mqtt'],
    'house-2': ['mqtt'],
    'house-3': ['mqtt'],
    'army-base': ['mqtt'],
  };

  const assetPosture = (id: string) => {
    const exposure = assetExposure[id] || ['mqtt'];
    let rank = Math.max(-1, ...exposure.map(v => vstats[v].rank));
    const live = siteData?.[id];
    const stale = isStale(live);
    const fault = live?.latest?.status === 'fault';
    // Loss of telemetry or a fault on an exposed feeder is itself a cyber signal
    // (possible DoS / disconnect) — treat as at least guarded.
    if (stale || fault) rank = Math.max(rank, fault ? 2 : 0);
    if (id === 'pv-plant' && halted) rank = 3;
    const opState = halted && id === 'pv-plant' ? 'HALTED'
      : stale ? 'NO TELEMETRY'
      : fault ? 'FAULT'
      : 'online';
    return { level: rankToLevel(rank), exposure, opState };
  };

  return (
    <section className="sec-posture" aria-label="Security posture overview">
      <div className={`posture-banner level-${overall.key}`}>
        <div className="banner-left">
          <span className="banner-eyebrow">DISTRICT THREAT LEVEL</span>
          <span className="banner-level">{overall.label}</span>
          <span className="banner-note">
            {monitorOnline ? 'SIEM monitor live · CY-LIM-042 · Ktima Elia district'
              : 'SIEM monitor unreachable — showing last known state'}
          </span>
        </div>
        <div className="banner-kpis">
          <div className="kpi kpi-crit">
            <span className="kpi-value">{totalCritical}</span>
            <span className="kpi-label">Critical</span>
          </div>
          <div className="kpi kpi-high">
            <span className="kpi-value">{totalHigh}</span>
            <span className="kpi-label">High</span>
          </div>
          <div className="kpi">
            <span className="kpi-value">{blockedCount}</span>
            <span className="kpi-label">Blocked IPs</span>
          </div>
          <div className="kpi">
            <span className="kpi-value">{last24h}</span>
            <span className="kpi-label">Events · 24h</span>
          </div>
        </div>
      </div>

      <h3 className="posture-heading">Threat Vectors</h3>
      <div className="vector-grid">
        {vectors.map(v => {
          const s = vstats[v];
          const m = VECTOR_META[v];
          return (
            <div key={v} className={`vector-card level-${s.level.key}`}>
              <div className="vector-head">
                <span className="vector-icon" aria-hidden="true">{m.icon}</span>
                <div className="vector-titles">
                  <span className="vector-title">{m.title}</span>
                  <span className="vector-sub">{m.sub}</span>
                </div>
                <span className={`posture-led led-${s.level.key}`} title={s.level.label} />
              </div>
              <div className="vector-status">{s.level.label}</div>
              <div className="vector-counts">
                <span className="vc crit">{s.critical} crit</span>
                <span className="vc high">{s.high} high</span>
                <span className="vc total">{s.total} total</span>
              </div>
              <div className="vector-last">
                {s.last ? `last: ${s.last.message} · ${relTime(s.last.timestamp)}`
                  : 'no events observed'}
              </div>
            </div>
          );
        })}
      </div>

      <h3 className="posture-heading">Asset Security Posture</h3>
      <div className="asset-grid">
        {MAP_SITES.map(site => {
          const p = assetPosture(site.id);
          const typeLabel = site.type === 'house' ? 'House'
            : site.type === 'plant' ? 'PV Plant · Substation' : 'Army Base · Consumer';
          return (
            <div key={site.id} className={`asset-card level-${p.level.key}`}>
              <div className="asset-head">
                <span className={`posture-led led-${p.level.key}`} />
                <div className="asset-titles">
                  <span className="asset-name">{site.name}</span>
                  <span className="asset-type">{typeLabel}</span>
                </div>
              </div>
              <div className="asset-level">{p.level.label}</div>
              <div className="asset-exposure">
                {p.exposure.map(v => (
                  <span key={v} className={`exposure-chip chip-${v}`}>{v}</span>
                ))}
              </div>
              <div className={`asset-op op-${p.opState === 'online' ? 'ok' : 'bad'}`}>
                {p.opState === 'online' ? '● link online' : `▲ ${p.opState}`}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
};

export default SecurityPosture;
