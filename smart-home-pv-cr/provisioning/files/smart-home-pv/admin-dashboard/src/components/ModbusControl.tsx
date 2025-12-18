import React, { useState } from 'react';
import './ModbusControl.css';

interface ModbusControlProps {
  token: string;
}

const ModbusControl: React.FC<ModbusControlProps> = () => {
  const [coilAddress, setCoilAddress] = useState('1');
  const [coilValue, setCoilValue] = useState(false);
  const [registerAddress, setRegisterAddress] = useState('1');
  const [registerValue, setRegisterValue] = useState('0');
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);

  const handleWriteCoil = async () => {
    setLoading(true);
    setResult('');
    try {
      // Note: This would call a backend API endpoint that performs the Modbus write
      // For the cyber range, students need to use pymodbus directly
      setResult(`⚠️ Direct Modbus control requires pymodbus client.\nUse: client.write_coil(${coilAddress}, ${coilValue})`);
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
      setResult(`⚠️ Direct Modbus control requires pymodbus client.\nUse: client.write_register(${registerAddress}, ${registerValue})`);
    } catch (error) {
      setResult(`Error: ${error}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modbus-control">
      <div className="page-header">
        <h2>Modbus TCP Control</h2>
        <p>Industrial protocol interface</p>
      </div>

      <div className="protocol-info">
        <div className="info-badge">
          <span className="badge-label">Protocol:</span>
          <span className="badge-value">Modbus TCP</span>
        </div>
        <div className="info-badge">
          <span className="badge-label">Port:</span>
          <span className="badge-value">502</span>
        </div>
        <div className="info-badge">
          <span className="badge-label">Unit ID:</span>
          <span className="badge-value">1</span>
        </div>
        <div className="info-badge">
          <span className="badge-label">Status:</span>
          <span className="badge-value status-online">Online</span>
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
        <h3>Register Map Reference</h3>
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
              <td>System Enable/Disable</td>
              <td className="access-rw">R/W</td>
              <td>0-1</td>
            </tr>
            <tr>
              <td className="addr-cell">1</td>
              <td className="type-cell">Coil</td>
              <td>Emergency Stop</td>
              <td className="access-rw">R/W</td>
              <td>0-1</td>
            </tr>
            <tr>
              <td className="addr-cell">0</td>
              <td className="type-cell">Register</td>
              <td>Power Setpoint (W)</td>
              <td className="access-rw">R/W</td>
              <td>0-7600</td>
            </tr>
            <tr>
              <td className="addr-cell">1</td>
              <td className="type-cell">Register</td>
              <td>Voltage Setpoint (V)</td>
              <td className="access-rw">R/W</td>
              <td>0-600</td>
            </tr>
            <tr>
              <td className="addr-cell">100</td>
              <td className="type-cell">Register</td>
              <td>Current Power Output</td>
              <td className="access-r">R</td>
              <td>0-7600</td>
            </tr>
            <tr>
              <td className="addr-cell">101</td>
              <td className="type-cell">Register</td>
              <td>Grid Voltage</td>
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
          <p>This interface provides direct access to industrial control functions. Unauthorized modifications may disrupt power production and damage equipment. All actions are logged and monitored.</p>
        </div>
      </div>
    </div>
  );
};

export default ModbusControl;
