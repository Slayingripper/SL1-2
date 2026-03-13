import React, { useState } from 'react';
import axios from 'axios';
import './Login.css';
import { logAdminActivity, useAdminActivityCapture } from '../utils/activityLogger';

interface LoginProps {
  onLoginSuccess: (token: string) => void;
}

const Login: React.FC<LoginProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useAdminActivityCapture('login');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    void logAdminActivity({
      action: 'login_submitted',
      eventType: 'submit',
      page: 'login',
      target: 'login-form',
      details: {
        field: 'username',
        value: username || 'empty',
      },
    });

    try {
      const response = await axios.post('/api/admin/login', {
        username,
        password,
      });

      if (response.data.token) {
        localStorage.setItem('pv_admin_token', response.data.token);
        void logAdminActivity({
          action: 'login_success',
          eventType: 'authentication',
          page: 'login',
          target: 'login-form',
          actor: username,
          details: {
            outcome: 'success',
          },
        }, response.data.token);
        onLoginSuccess(response.data.token);
      } else {
        setError('Invalid response from server');
      }
    } catch (err: any) {
      void logAdminActivity({
        action: 'login_failed',
        eventType: 'authentication',
        page: 'login',
        target: 'login-form',
        actor: username || 'unknown',
        details: {
          outcome: err.response?.status === 401 ? 'invalid_credentials' : 'request_failed',
          status: err.response?.status || 'network_error',
        },
      });
      if (err.response?.status === 401) {
        setError('Invalid credentials. Access denied.');
      } else {
        setError('Authentication failed. Check network connection.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-background">
        <div className="grid-overlay"></div>
      </div>
      
      <div className="login-box">
        <div className="login-header">
          <div className="system-logo">
            <div className="logo-icon">⚡</div>
            <div className="logo-text">
              <h1>PV SCADA HMI</h1>
              <p>Solar Energy Management System</p>
            </div>
          </div>
          <div className="system-status">
            <span className="status-indicator status-operational"></span>
            <span>System Operational</span>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <h2>Secure Access Portal</h2>
          
          {error && (
            <div className="error-banner">
              <span className="error-icon">⚠</span>
              <span>{error}</span>
            </div>
          )}

          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              autoComplete="username"
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              autoComplete="current-password"
              required
              disabled={loading}
            />
          </div>

          <button type="submit" className="login-button" disabled={loading}>
            {loading ? (
              <>
                <span className="spinner"></span>
                Authenticating...
              </>
            ) : (
              <>
                <span>🔐</span>
                Access Control System
              </>
            )}
          </button>

          <div className="login-footer">
            <p className="security-notice">
              ⓘ This system is protected by enterprise-grade security.
              Unauthorized access attempts are logged and monitored.
            </p>
          </div>
        </form>

        <div className="system-info">
          <div className="info-item">
            <span className="info-label">System Version:</span>
            <span className="info-value">v2.4.1</span>
          </div>
          <div className="info-item">
            <span className="info-label">Protocol:</span>
            <span className="info-value">HTTPS/TLS 1.3</span>
          </div>
          <div className="info-item">
            <span className="info-label">Region:</span>
            <span className="info-value">North America</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
