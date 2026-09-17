import React, { useState, useEffect } from 'react';
import './ModbusControl.css';
import { logAdminActivity } from '../utils/activityLogger';

interface ModbusControlProps {
  token: string;
}

interface SystemInfo {
  modbus?: { port?: number; listening?: boolean };
  session?: string;
  firmware?: string;
  site?: string;
  controller_ips?: string[];
  server_time?: string;
}

const STALE_AFTER_S = 30;

const ModbusControl: React.FC<ModbusControlProps> = ({ token }) => {
  const [coilAddress, setCoilAddress] = useState('1');
  const [coilValue, setCoilValue] = useState(false);
  const [registerAddress, setRegisterAddress] = useState('1');
  const [registerValue, setRegisterValue] = useState('0');
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);

  // Live field-device state, same source the Plant Overview / Area Map read.
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

  const site = info?.site || 'CY-LIM-042';
  const modbusPort = info?.modbus?.port ?? 502;
  const stale = infoAgeS == null || infoAgeS > STALE_AFTER_S;
  const online = !stale && !!info?.modbus?.listening;
  const linkClass = stale ? 'led-stale' : online ? 'led-ok' : 'led-crit';
  const linkText = stale ? 'NO DATA' : online ? 'ONLINE' : 'OFFLINE';

  const handleWriteCoil = async () => {
    setLoading(true);
    setResult('');
    try {
      void logAdminActivity({
        action: 'modbus_write_coil_requested',
        eventType: 'control',
        page: 'dashboard/modbus',
        target: 'write-coil',
        details: {
          address: coilAddress,
          value: coilValue ? 'true' : 'false',
        },
      }, token);
      // Note: This would call a backend API endpoint that performs the Modbus write.
      // For the cyber range, students issue the write over the wire with pymodbus.
      setResult(
        `⚠️ Direct Modbus control requires a pymodbus client.\n` +
        `Target: ${site} substation TX-01 · Modbus/TCP ${modbusPort} · unit 1\n` +
        `Use: client.write_coil(${coilAddress}, ${coilValue}, slave=1)`
      );
    } catch (error) {
      void logAdminActivity({
        action: 'modbus_write_coil_failed',
        eventType: 'control',
        page: 'dashboard/modbus',
        target: 'write-coil',
        details: {
          address: coilAddress,
          outcome: 'error',
        },
      }, token);
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
        details: {
          register: registerAddress,
          value: registerValue,
        },
      }, token);
      setResult(
        `⚠️ Direct Modbus control requires a pymodbus client.\n` +
        `Target: ${site} substation TX-01 · Modbus/TCP ${modbusPort} · unit 1\n` +
        `Use: client.write_register(${registerAddress}, ${registerValue}, slave=1)`
      );
    } catch (error) {
      void logAdminActivity({
        action: 'modbus_write_register_failed',
        eventType: 'control',
        page: 'dashboard/modbus',
        target: 'write-register',
        details: {
          register: registerAddress,
          outcome: 'error',
        },
      }, token);
      setResult(`Error: ${error}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modbus-control">
      <div className="page-header">
        <h2>Modbus TCP Control</h2>
        <p>Substation TX-01 · Limassol · {site} controller · Modbus/TCP field interface</p>
      </div>

      <div className="protocol-info">
        <div className="info-badge">
          <span className="badge-label">Protocol:</span>
          <span className="badge-value">Modbus TCP</span>
        </div>
        <div className="info-badge">
          <span className="badge-label">Endpoint:</span>
          <span className="badge-value">{site} : {modbusPort}</span>
        </div>
        <div className="info-badge">
          <span className="badge-label">Unit ID:</span>
          <span className="badge-value">1</span>
        </div>
        <div className="info-badge">
          <span className="badge-label">Firmware:</span>
          <span className="badge-value">{info?.firmware || '—'}</span>
        </div>
        <div className="info-badge">
          <span className="badge-label">Link:</span>
          <span className="badge-value badge-live">
            <span className={`status-led-dot ${linkClass}`} />
            {linkText}
          </span>
        </div>
      </div>

      <div className="control-panels">
        <div className="control-panel">
          <h3>Coil Control (FC 05)</h3>
          <p className="panel-description">Write Single Coil - Control digital outputs</p>

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

          <button
            className="execute-btn"
            onClick={handleWriteCoil}
            disabled={loading}
          >
            {loading ? 'Executing...' : '⚡ Write Coil'}
          </button>
        </div>

        <div className="control-panel">
          <h3>Register Control (FC 16)</h3>
          <p className="panel-description">Write Single Register - Control analog outputs</p>

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

          <button
            className="execute-btn"
            onClick={handleWriteRegister}
            disabled={loading}
          >
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
        <h3>Register Map Reference · {site} / SolarEdge SE7600H</h3>
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
            <tr>
              <td className="addr-cell">0</td>
              <td className="type-cell">Coil</td>
              <td>Inverter Enable / Disable</td>
              <td className="access-rw">R/W</td>
              <td>0-1</td>
            </tr>
            <tr className="reg-critical">
              <td className="addr-cell">1</td>
              <td className="type-cell">Coil</td>
              <td>Emergency Stop (HALT) — forces AC output to 0 kW</td>
              <td className="access-rw">R/W</td>
              <td>0-1</td>
            </tr>
            <tr>
              <td className="addr-cell">0</td>
              <td className="type-cell">Register</td>
              <td>Active Power Setpoint (W)</td>
              <td className="access-rw">R/W</td>
              <td>0-7600</td>
            </tr>
            <tr>
              <td className="addr-cell">1</td>
              <td className="type-cell">Register</td>
              <td>Grid Voltage Setpoint (V)</td>
              <td className="access-rw">R/W</td>
              <td>0-600</td>
            </tr>
            <tr>
              <td className="addr-cell">100</td>
              <td className="type-cell">Register</td>
              <td>Current AC Output (W)</td>
              <td className="access-r">R</td>
              <td>0-7600</td>
            </tr>
            <tr>
              <td className="addr-cell">101</td>
              <td className="type-cell">Register</td>
              <td>Grid Voltage (V)</td>
              <td className="access-r">R</td>
              <td>0-600</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="security-notice">
        <div className="notice-icon">⚠️</div>
        <div className="notice-content">
          <h4>Security Notice</h4>
          <p>This interface provides direct access to the {site} substation control functions over Modbus/TCP. The protocol carries no authentication — a write to coil 1 halts inverter production plant-wide. Unauthorized modifications may disrupt power production and damage equipment. All actions are logged and monitored by the Blue Team defense console.</p>
        </div>
      </div>
    </div>
  );
};

export default ModbusControl;
