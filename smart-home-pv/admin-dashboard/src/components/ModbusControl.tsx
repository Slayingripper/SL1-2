import React, { useState, useEffect, useMemo } from 'react';
import './ModbusControl.css';
import { logAdminActivity } from '../utils/activityLogger';
import { MAP_SITES, siteById } from '../data/mapSites';
import { SiteLive } from './Dashboard';

interface ModbusControlProps {
  token: string;
  siteData?: Record<string, SiteLive>;
}

interface SystemInfo {
  modbus?: { port?: number; listening?: boolean };
  session?: string;
  firmware?: string;
  site?: string;
  controller_ips?: string[];
  server_time?: string;
}

interface RegisterRow {
  addr: number;
  type: 'Coil' | 'Register';
  desc: string;
  access: 'R/W' | 'R';
  range: string;
  critical?: boolean;
}

interface AssetProfile {
  id: string;
  label: string;        // endpoint/site label
  title: string;        // page subtitle target
  equipment: string;
  serial: string;
  feeder: string;
  unitId: number;
  consumer: boolean;
  registers: RegisterRow[];
  notice: string;
}

const STALE_AFTER_S = 30;

const ModbusControl: React.FC<ModbusControlProps> = ({ token, siteData }) => {
  const [assetId, setAssetId] = useState('controller');
  const [coilAddress, setCoilAddress] = useState('1');
  const [coilValue, setCoilValue] = useState(false);
  const [registerAddress, setRegisterAddress] = useState('0');
  const [registerValue, setRegisterValue] = useState('0');
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);

  // Live controller state (only the controller exposes /api/system/info).
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [infoAgeS, setInfoAgeS] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const resp = await fetch('/api/system/info');
        if (!resp.ok) return;
        const data = await resp.json();
        if (!cancelled) {
          setInfo(data);
          setInfoAgeS(0);
        }
      } catch {
        /* non-fatal — keep last known state, LED goes stale */
      }
    };
    void load();
    const iv = setInterval(load, 10000);
    const age = setInterval(() => setInfoAgeS(a => (a == null ? a : a + 1)), 1000);
    return () => { cancelled = true; clearInterval(iv); clearInterval(age); };
  }, []);

  const modbusPort = info?.modbus?.port ?? 502;

  const profile: AssetProfile = useMemo(() => {
    if (assetId === 'controller') {
      const cap = 7600; // SE7600H rated W
      return {
        id: info?.site || 'CY-LIM-042',
        label: info?.site || 'CY-LIM-042',
        title: 'Plant controller · Modbus/TCP field interface',
        equipment: 'SolarEdge SE7600H',
        serial: info?.session ? `sess ${info.session}` : 'SE76-CY-0042',
        feeder: 'Substation TX-01 · Limassol',
        unitId: 1,
        consumer: false,
        registers: producerRegisters(cap),
        notice: `This interface provides direct access to the ${info?.site || 'CY-LIM-042'} controller over Modbus/TCP. The protocol carries no authentication — a write to coil 1 halts inverter production plant-wide.`,
      };
    }
    const meta = siteById(assetId)!;
    const idx = MAP_SITES.findIndex(s => s.id === assetId);
    if (meta.type === 'army') {
      const load = Math.round((meta.ratedLoadKw ?? 30) * 1000);
      return {
        id: meta.id,
        label: meta.name,
        title: `${meta.name} · ${meta.feeder}`,
        equipment: meta.model,
        serial: meta.serial,
        feeder: meta.feeder,
        unitId: idx + 2,
        consumer: true,
        registers: consumerRegisters(load),
        notice: `This interface controls the ${meta.name} LV switchboard over Modbus/TCP. A write to coil 1 sheds load feeding a restricted military installation — unauthorized operation may cut power to critical systems.`,
      };
    }
    // house or plant → producer profile
    const cap = Math.round((meta.capacityKw ?? 5) * 1000);
    return {
      id: meta.id,
      label: meta.name,
      title: `${meta.name} · ${meta.feeder}`,
      equipment: meta.model,
      serial: meta.serial,
      feeder: meta.feeder,
      unitId: idx + 2,
      consumer: false,
      registers: producerRegisters(cap),
      notice: `This interface provides direct access to the ${meta.name} ${meta.type === 'plant' ? 'central inverter / substation' : 'inverter'} over Modbus/TCP. The protocol carries no authentication — a write to coil 1 forces AC output to 0 kW.`,
    };
  }, [assetId, info]);

  // Link LED: controller uses /api/system/info; map sites use MQTT freshness.
  const link = useMemo(() => {
    if (assetId === 'controller') {
      const stale = infoAgeS == null || infoAgeS > STALE_AFTER_S;
      const online = !stale && !!info?.modbus?.listening;
      return { cls: stale ? 'led-stale' : online ? 'led-ok' : 'led-crit', text: stale ? 'NO DATA' : online ? 'ONLINE' : 'OFFLINE' };
    }
    const latest = siteData?.[assetId]?.latest;
    const stale = !latest || Date.now() / 1000 - Number(latest.ts ?? 0) > STALE_AFTER_S;
    if (stale) return { cls: 'led-stale', text: 'NO DATA' };
    if (latest?.status === 'fault') return { cls: 'led-crit', text: 'FAULT' };
    return { cls: 'led-ok', text: 'ONLINE' };
  }, [assetId, info, infoAgeS, siteData]);

  const targetLine = `Target: ${profile.label} · Modbus/TCP ${modbusPort} · unit ${profile.unitId}`;

  const handleWriteCoil = async () => {
    setLoading(true);
    setResult('');
    try {
      void logAdminActivity({
        action: 'modbus_write_coil_requested',
        eventType: 'control',
        page: 'dashboard/modbus',
        target: 'write-coil',
        details: { asset: profile.id, address: coilAddress, value: coilValue ? 'true' : 'false' },
      }, token);
      setResult(
        `⚠️ Direct Modbus control requires a pymodbus client.\n` +
        `${targetLine}\n` +
        `Use: client.write_coil(${coilAddress}, ${coilValue}, slave=${profile.unitId})`
      );
    } catch (error) {
      setResult(`Error: ${error}`);
    } finally {
      setLoading(false);
    }
  };

  const handleWriteRegister = async () => {
    setLoading(true);
    setResult('');
    try {
      void logAdminActivity({
        action: 'modbus_write_register_requested',
        eventType: 'control',
        page: 'dashboard/modbus',
        target: 'write-register',
        details: { asset: profile.id, register: registerAddress, value: registerValue },
      }, token);
      setResult(
        `⚠️ Direct Modbus control requires a pymodbus client.\n` +
        `${targetLine}\n` +
        `Use: client.write_register(${registerAddress}, ${registerValue}, slave=${profile.unitId})`
      );
    } catch (error) {
      setResult(`Error: ${error}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modbus-control">
      <div className="page-header page-header-row">
        <div>
          <h2>Modbus TCP Control</h2>
          <p>{profile.title}</p>
        </div>
        <label className="asset-select-label">
          <span>Asset</span>
          <select
            className="asset-select"
            value={assetId}
            onChange={e => setAssetId(e.target.value)}
            aria-label="Select Modbus target asset"
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

      <div className="protocol-info">
        <div className="info-badge">
          <span className="badge-label">Protocol:</span>
          <span className="badge-value">Modbus TCP</span>
        </div>
        <div className="info-badge">
          <span className="badge-label">Endpoint:</span>
          <span className="badge-value">{profile.label} : {modbusPort}</span>
        </div>
        <div className="info-badge">
          <span className="badge-label">Unit ID:</span>
          <span className="badge-value">{profile.unitId}</span>
        </div>
        <div className="info-badge">
          <span className="badge-label">Equipment:</span>
          <span className="badge-value">{profile.equipment}</span>
        </div>
        <div className="info-badge">
          <span className="badge-label">Link:</span>
          <span className="badge-value badge-live">
            <span className={`status-led-dot ${link.cls}`} />
            {link.text}
          </span>
        </div>
      </div>

      <div className="control-panels">
        <div className="control-panel">
          <h3>Coil Control (FC 05)</h3>
          <p className="panel-description">
            {profile.consumer ? 'Write Single Coil — breaker / load-shed outputs' : 'Write Single Coil — inverter digital outputs'}
          </p>

          <div className="form-group">
            <label>Coil Address</label>
            <input
              type="number"
              value={coilAddress}
              onChange={(e) => setCoilAddress(e.target.value)}
              min="0"
              max="65535"
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label>Value</label>
            <div className="toggle-group">
              <button
                className={`toggle-btn ${!coilValue ? 'active' : ''}`}
                onClick={() => setCoilValue(false)}
                disabled={loading}
              >
                OFF (0x0000)
              </button>
              <button
                className={`toggle-btn ${coilValue ? 'active' : ''}`}
                onClick={() => setCoilValue(true)}
                disabled={loading}
              >
                ON (0xFF00)
              </button>
            </div>
          </div>

          <button className="execute-btn" onClick={handleWriteCoil} disabled={loading}>
            {loading ? 'Executing...' : '⚡ Write Coil'}
          </button>
        </div>

        <div className="control-panel">
          <h3>Register Control (FC 16)</h3>
          <p className="panel-description">
            {profile.consumer ? 'Write Single Register — load / setpoint outputs' : 'Write Single Register — inverter analog outputs'}
          </p>

          <div className="form-group">
            <label>Register Address</label>
            <input
              type="number"
              value={registerAddress}
              onChange={(e) => setRegisterAddress(e.target.value)}
              min="0"
              max="65535"
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label>Value (0-65535)</label>
            <input
              type="number"
              value={registerValue}
              onChange={(e) => setRegisterValue(e.target.value)}
              min="0"
              max="65535"
              disabled={loading}
            />
          </div>

          <button className="execute-btn" onClick={handleWriteRegister} disabled={loading}>
            {loading ? 'Executing...' : '⚡ Write Register'}
          </button>
        </div>
      </div>

      {result && (
        <div className="result-panel">
          <h3>Execution Result</h3>
          <pre className="result-output">{result}</pre>
        </div>
      )}

      <div className="register-map">
        <h3>Register Map Reference · {profile.label} / {profile.equipment}</h3>
        <table className="register-table">
          <thead>
            <tr>
              <th>Address</th>
              <th>Type</th>
              <th>Description</th>
              <th>Access</th>
              <th>Range</th>
            </tr>
          </thead>
          <tbody>
            {profile.registers.map((r, i) => (
              <tr key={`${r.type}-${r.addr}-${i}`} className={r.critical ? 'reg-critical' : ''}>
                <td className="addr-cell">{r.addr}</td>
                <td className="type-cell">{r.type}</td>
                <td>{r.desc}</td>
                <td className={r.access === 'R/W' ? 'access-rw' : 'access-r'}>{r.access}</td>
                <td>{r.range}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="security-notice">
        <div className="notice-icon">⚠️</div>
        <div className="notice-content">
          <h4>Security Notice</h4>
          <p>{profile.notice} Unauthorized modifications may disrupt power and damage equipment. All actions are logged and monitored by the Blue Team defense console.</p>
        </div>
      </div>
    </div>
  );
};

function producerRegisters(capW: number): RegisterRow[] {
  return [
    { addr: 0, type: 'Coil', desc: 'Inverter Enable / Disable', access: 'R/W', range: '0-1' },
    { addr: 1, type: 'Coil', desc: 'Emergency Stop (HALT) — forces AC output to 0 kW', access: 'R/W', range: '0-1', critical: true },
    { addr: 0, type: 'Register', desc: 'Active Power Setpoint (W)', access: 'R/W', range: `0-${capW}` },
    { addr: 1, type: 'Register', desc: 'Grid Voltage Setpoint (V)', access: 'R/W', range: '0-600' },
    { addr: 100, type: 'Register', desc: 'Current AC Output (W)', access: 'R', range: `0-${capW}` },
    { addr: 101, type: 'Register', desc: 'Grid Voltage (V)', access: 'R', range: '0-600' },
  ];
}

function consumerRegisters(loadW: number): RegisterRow[] {
  return [
    { addr: 0, type: 'Coil', desc: 'Main Breaker Close / Open', access: 'R/W', range: '0-1' },
    { addr: 1, type: 'Coil', desc: 'Load Shed (Emergency) — drops non-critical feeders', access: 'R/W', range: '0-1', critical: true },
    { addr: 2, type: 'Coil', desc: 'Backup Genset Start command', access: 'R/W', range: '0-1' },
    { addr: 0, type: 'Register', desc: 'Load Limit Setpoint (W)', access: 'R/W', range: `0-${loadW}` },
    { addr: 100, type: 'Register', desc: 'Current Load (W)', access: 'R', range: `0-${loadW}` },
    { addr: 101, type: 'Register', desc: 'Bus Voltage (V)', access: 'R', range: '0-600' },
    { addr: 102, type: 'Register', desc: 'UPS State of Charge (%)', access: 'R', range: '0-100' },
  ];
}

export default ModbusControl;
