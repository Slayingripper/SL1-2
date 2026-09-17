import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import './BlueTeamDashboard.css';

interface BlueTeamDashboardProps {
  token: string;
  onLogout: () => void;
}

interface DefenseSettings {
  login_rate_limit: boolean;
  rate_limit_per_minute: number;
  modbus_write_restricted: boolean;
  telemetry_validation: boolean;
  telemetry_max_power_kw: number;
  telemetry_min_power_kw: number;
  xss_protection: boolean;
  ip_whitelist_enabled: boolean;
  ip_whitelist: string[];
  admin_session_timeout_minutes: number;
  alert_notification_tier: string;
  ip_blacklist_enabled: boolean;
  ip_blacklist: string[];
  inactivity_timeout_minutes: number;
}

interface OperatorUser {
  username: string;
  role: string;
  description: string;
}

interface SecurityEvent {
  timestamp: string;
  severity: string;
  category: string;
  message: string;
  details?: string;
  source?: string;
  ip?: string;
}

const DEFAULT_SETTINGS: DefenseSettings = {
  login_rate_limit: false,
  rate_limit_per_minute: 5,
  modbus_write_restricted: false,
  telemetry_validation: false,
  telemetry_max_power_kw: 10,
  telemetry_min_power_kw: -2,
  xss_protection: false,
  ip_whitelist_enabled: false,
  ip_whitelist: [],
  admin_session_timeout_minutes: 30,
  alert_notification_tier: 'critical',
  ip_blacklist_enabled: false,
  ip_blacklist: [],
  inactivity_timeout_minutes: 5,
};

const Toggle: React.FC<{ checked: boolean; onChange: (v: boolean) => void }> = ({ checked, onChange }) => (
  <button
    type="button"
    className={`bt-toggle ${checked ? 'on' : ''}`}
    onClick={() => onChange(!checked)}
    aria-pressed={checked}
  >
    <span className="bt-toggle-knob" />
  </button>
);

const IpListEditor: React.FC<{
  ips: string[];
  placeholder: string;
  onChange: (ips: string[]) => void;
}> = ({ ips, placeholder, onChange }) => {
  const [draft, setDraft] = useState('');
  const add = () => {
    const v = draft.trim();
    if (v && !ips.includes(v)) onChange([...ips, v]);
    setDraft('');
  };
  return (
    <div className="bt-iplist">
      <div className="bt-iplist-row">
        <input
          value={draft}
          placeholder={placeholder}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') add(); }}
        />
        <button type="button" className="bt-iplist-add" onClick={add}>+</button>
      </div>
      {ips.length > 0 && (
        <div className="bt-iplist-chips">
          {ips.map(ip => (
            <span key={ip} className="bt-chip">
              {ip}
              <button type="button" onClick={() => onChange(ips.filter(i => i !== ip))}>×</button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

const UserPasswordCard: React.FC<{
  user: OperatorUser;
  token: string;
  onExpired: () => void;
}> = ({ user, token, onExpired }) => {
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const reset = async () => {
    setMessage(null);
    if (newPw !== confirmPw) {
      setMessage({ ok: false, text: 'Password confirmation does not match' });
      return;
    }
    setBusy(true);
    try {
      await axios.post('/api/blueteam/users/change-password', {
        username: user.username,
        new_password: newPw,
        confirm_password: confirmPw,
      }, { headers: { Authorization: `Bearer ${token}` } });
      setMessage({ ok: true, text: `Password updated for ${user.username}` });
      setNewPw('');
      setConfirmPw('');
    } catch (err: any) {
      if (err?.response?.status === 401) onExpired();
      else setMessage({ ok: false, text: err?.response?.data?.error || 'Password reset failed' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="bt-panel bt-user-card">
      <div className="bt-user-head">
        <div className="bt-user-avatar">{user.username.slice(0, 2).toUpperCase()}</div>
        <div>
          <div className="bt-control-title">{user.username}</div>
          <span className={`bt-role-badge role-${user.role}`}>{user.role.toUpperCase()}</span>
        </div>
      </div>
      <p className="bt-panel-note">{user.description}</p>
      <label className="bt-field">
        <span>NEW PASSWORD (MIN 6 CHARS)</span>
        <input type="password" placeholder="new password" value={newPw} onChange={e => setNewPw(e.target.value)} />
      </label>
      <label className="bt-field">
        <span>CONFIRM NEW PASSWORD</span>
        <input type="password" placeholder="confirm new password" value={confirmPw} onChange={e => setConfirmPw(e.target.value)} />
      </label>
      {message && <div className={`bt-pw-msg ${message.ok ? 'ok' : 'err'}`}>{message.text}</div>}
      <button type="button" className="bt-btn-secondary" disabled={busy} onClick={reset}>
        RESET PASSWORD
      </button>
    </section>
  );
};

const BlueTeamDashboard: React.FC<BlueTeamDashboardProps> = ({ token, onLogout }) => {
  const [settings, setSettings] = useState<DefenseSettings>(DEFAULT_SETTINGS);
  const [defenseActive, setDefenseActive] = useState(false);
  const [controlsEngaged, setControlsEngaged] = useState(0);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [plantStatus, setPlantStatus] = useState('UNKNOWN');
  const [now, setNow] = useState(new Date());
  const [sessionLeft, setSessionLeft] = useState(5 * 60);
  const [applyFlash, setApplyFlash] = useState('');
  const [tab, setTab] = useState<'defenses' | 'users'>('defenses');
  const [users, setUsers] = useState<OperatorUser[]>([]);
  const loggedOut = useRef(false);

  const authHeaders = { Authorization: `Bearer ${token}` };

  const handleExpired = useCallback(() => {
    if (!loggedOut.current) {
      loggedOut.current = true;
      onLogout();
    }
  }, [onLogout]);

  const refreshStatus = useCallback(async () => {
    try {
      const [statusResp, eventsResp, defResp] = await Promise.all([
        axios.get('/api/status'),
        axios.get('/api/admin/security/events', { headers: authHeaders }),
        axios.get('/api/blueteam/defense_status'),
      ]);
      setPlantStatus(statusResp.data.status || 'UNKNOWN');
      setEvents((eventsResp.data.events || []).slice().reverse());
      setDefenseActive(!!defResp.data.active);
      setControlsEngaged(defResp.data.controls_enabled || 0);
    } catch (err: any) {
      if (err?.response?.status === 401 || err?.response?.status === 403) handleExpired();
    }
  }, [token, handleExpired]);

  useEffect(() => {
    (async () => {
      try {
        const resp = await axios.get('/api/blueteam/settings', { headers: authHeaders });
        if (resp.data.settings) setSettings({ ...DEFAULT_SETTINGS, ...resp.data.settings });
        setDefenseActive(!!resp.data.active);
      } catch (err: any) {
        if (err?.response?.status === 401) handleExpired();
      }
    })();
    refreshStatus();
    const poll = setInterval(refreshStatus, 5000);
    return () => clearInterval(poll);
  }, []);

  useEffect(() => {
    if (tab !== 'users') return;
    (async () => {
      try {
        const resp = await axios.get('/api/blueteam/users', { headers: authHeaders });
        setUsers(resp.data.users || []);
      } catch (err: any) {
        if (err?.response?.status === 401) handleExpired();
      }
    })();
  }, [tab]);

  useEffect(() => {
    const tick = setInterval(() => {
      setNow(new Date());
      setSessionLeft(prev => {
        if (prev <= 1) {
          handleExpired();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(tick);
  }, [handleExpired]);

  const set = <K extends keyof DefenseSettings>(key: K, value: DefenseSettings[K]) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  const applyDefenses = async () => {
    try {
      const resp = await axios.put('/api/blueteam/settings', settings, { headers: authHeaders });
      if (resp.data.settings) setSettings({ ...DEFAULT_SETTINGS, ...resp.data.settings });
      setSessionLeft(settings.inactivity_timeout_minutes * 60);
      setApplyFlash('DEFENSES APPLIED');
      setTimeout(() => setApplyFlash(''), 3000);
      refreshStatus();
    } catch (err: any) {
      if (err?.response?.status === 401) handleExpired();
      else {
        setApplyFlash('APPLY FAILED');
        setTimeout(() => setApplyFlash(''), 3000);
      }
    }
  };

  const logOffReset = async () => {
    try {
      await axios.post('/api/blueteam/logout', {}, { headers: authHeaders });
    } catch { /* token may already be gone */ }
    handleExpired();
  };

  const resetPlant = async () => {
    try {
      await axios.post('/api/plant/reset', {}, { headers: authHeaders });
      refreshStatus();
    } catch (err: any) {
      if (err?.response?.status === 401) handleExpired();
    }
  };

  const fmtClock = now.toLocaleTimeString('en-GB', { hour12: false });
  const fmtDate = now.toLocaleDateString('en-GB', { month: 'short', day: 'numeric', year: 'numeric' }).toUpperCase();
  const sessionMin = String(Math.floor(sessionLeft / 60)).padStart(2, '0');
  const sessionSec = String(sessionLeft % 60).padStart(2, '0');

  const severityClass = (sev: string) => {
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return 'sev-critical';
    if (s === 'high') return 'sev-high';
    if (s === 'medium') return 'sev-medium';
    return 'sev-low';
  };

  return (
    <div className="bt-console">
      <header className="bt-header">
        <div className="bt-header-left">
          <div className="bt-badge">BT</div>
          <div>
            <h1>BLUE TEAM DEFENSE CONSOLE</h1>
            <div className="bt-subtitle">UNIT CY-LIM-042 · HARDENING CONFIGURATION</div>
          </div>
        </div>
        <div className="bt-clock">
          <div className="bt-clock-time">{fmtClock}</div>
          <div className="bt-clock-date">{fmtDate}</div>
        </div>
        <div className="bt-header-right">
          <div className="bt-session">
            <span className="bt-session-dot" /> SESSION {sessionMin}:{sessionSec}
          </div>
          <button type="button" className="bt-logoff" onClick={logOffReset}>LOG OFF &amp; RESET</button>
        </div>
      </header>

      <div className="bt-statusbar">
        <div className={`bt-defense-state ${defenseActive ? 'active' : ''}`}>
          <span className="bt-state-dot" />
          DEFENSE SYSTEM {defenseActive ? 'ACTIVE' : 'INACTIVE'} · {controlsEngaged} CONTROLS ENGAGED
        </div>
        <div className="bt-autoreset">AUTO-RESET ON LOGOFF OR {settings.inactivity_timeout_minutes} MIN INACTIVITY</div>
      </div>

      <nav className="bt-tabs">
        <button
          type="button"
          className={`bt-tab ${tab === 'defenses' ? 'active' : ''}`}
          onClick={() => setTab('defenses')}
        >
          DEFENSES
        </button>
        <button
          type="button"
          className={`bt-tab ${tab === 'users' ? 'active' : ''}`}
          onClick={() => setTab('users')}
        >
          USERS
        </button>
      </nav>

      {tab === 'users' ? (
        <div className="bt-users-grid">
          {users.length === 0 && <div className="bt-events-empty">Loading operator accounts…</div>}
          {users.map(u => (
            <UserPasswordCard key={u.username} user={u} token={token} onExpired={handleExpired} />
          ))}
        </div>
      ) : (
      <div className="bt-grid">
        <div className="bt-column">
          <section className="bt-panel">
            <h2>ACCESS CONTROL</h2>
            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">Login Rate Limiting</div>
                  <div className="bt-control-desc">Throttle brute-force attempts on the admin login endpoint</div>
                </div>
                <Toggle checked={settings.login_rate_limit} onChange={v => set('login_rate_limit', v)} />
              </div>
              <label className="bt-field">
                <span>MAX LOGIN ATTEMPTS PER MINUTE</span>
                <input
                  type="number" min={1}
                  value={settings.rate_limit_per_minute}
                  disabled={!settings.login_rate_limit}
                  onChange={e => set('rate_limit_per_minute', Number(e.target.value) || 1)}
                />
              </label>
            </div>

            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">IP Blacklist</div>
                  <div className="bt-control-desc">Block known malicious IPs (manual entries below)</div>
                </div>
                <Toggle checked={settings.ip_blacklist_enabled} onChange={v => set('ip_blacklist_enabled', v)} />
              </div>
              <div className="bt-field">
                <span>BLACKLISTED IPS / SUBNETS</span>
                <IpListEditor
                  ips={settings.ip_blacklist}
                  placeholder="e.g. 203.0.113.45"
                  onChange={ips => set('ip_blacklist', ips)}
                />
              </div>
            </div>

            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">Admin Session Timeout</div>
                  <div className="bt-control-desc">Auto-expire logged-in admin sessions (below)</div>
                </div>
              </div>
              <label className="bt-field">
                <span>ADMIN SESSION TIMEOUT (MINUTES)</span>
                <input
                  type="number" min={1}
                  value={settings.admin_session_timeout_minutes}
                  onChange={e => set('admin_session_timeout_minutes', Number(e.target.value) || 1)}
                />
              </label>
            </div>
          </section>

        </div>

        <div className="bt-column">
          <section className="bt-panel">
            <h2>ICS PROTOCOL DEFENSES</h2>
            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">Modbus Write Protection</div>
                  <div className="bt-control-desc">Block unauthorized HALT writes over Modbus TCP</div>
                </div>
                <Toggle checked={settings.modbus_write_restricted} onChange={v => set('modbus_write_restricted', v)} />
              </div>
            </div>
          </section>

          <section className="bt-panel">
            <h2>WEB &amp; ALERTING</h2>
            <p className="bt-panel-note">NOTIFICATION POPUPS SHOW EFFECTS ONLY FOR SEVERITY &gt;= TIER</p>
            <label className="bt-field">
              <span>NOTIFICATION ALERT TIER</span>
              <select
                value={settings.alert_notification_tier}
                onChange={e => set('alert_notification_tier', e.target.value)}
              >
                <option value="critical">Critical only</option>
                <option value="high">High and above</option>
                <option value="medium">Medium and above</option>
                <option value="low">All alerts</option>
              </select>
            </label>
          </section>
        </div>

        <div className="bt-column">
          <section className="bt-panel">
            <h2>MITIGATION COMMANDS</h2>
            <p className="bt-panel-note">Toggle each mitigation and set its parameters. No code required — enabled controls are applied automatically on live traffic.</p>

            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">Telemetry Validation</div>
                  <div className="bt-control-desc">Reject telemetry outside the physical power bounds below</div>
                </div>
                <Toggle checked={settings.telemetry_validation} onChange={v => set('telemetry_validation', v)} />
              </div>
              <label className="bt-field">
                <span>MAX POWER (KW)</span>
                <input
                  type="number"
                  value={settings.telemetry_max_power_kw}
                  disabled={!settings.telemetry_validation}
                  onChange={e => set('telemetry_max_power_kw', Number(e.target.value))}
                />
              </label>
              <label className="bt-field">
                <span>MIN POWER (KW)</span>
                <input
                  type="number"
                  value={settings.telemetry_min_power_kw}
                  disabled={!settings.telemetry_validation}
                  onChange={e => set('telemetry_min_power_kw', Number(e.target.value))}
                />
              </label>
            </div>

            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">XSS / SQLi Filter</div>
                  <div className="bt-control-desc">Block script, event handlers and SQL injection signatures on web requests</div>
                </div>
                <Toggle checked={settings.xss_protection} onChange={v => set('xss_protection', v)} />
              </div>
            </div>

            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">IP Whitelist</div>
                  <div className="bt-control-desc">Only allow the IPs listed below to reach the API</div>
                </div>
                <Toggle checked={settings.ip_whitelist_enabled} onChange={v => set('ip_whitelist_enabled', v)} />
              </div>
              <div className="bt-field">
                <span>ALLOWED IPS / SUBNETS</span>
                <IpListEditor
                  ips={settings.ip_whitelist}
                  placeholder="e.g. 192.168.100.202"
                  onChange={ips => set('ip_whitelist', ips)}
                />
              </div>
            </div>
          </section>
        </div>

        <div className="bt-column bt-column-wide">
          <section className="bt-panel">
            <h2>SECURITY EVENT REVIEW</h2>
            <p className="bt-panel-note">Incidents and suspicious behavior logged by the SOC / admin for your review.</p>
            <div className="bt-events">
              {events.length === 0 && <div className="bt-events-empty">No security events recorded.</div>}
              {events.map((ev, i) => (
                <div key={`${ev.timestamp}-${i}`} className={`bt-event ${severityClass(ev.severity)}`}>
                  <div className="bt-event-top">
                    <span className={`bt-sev-badge ${severityClass(ev.severity)}`}>{(ev.severity || '').toUpperCase()}</span>
                    <span className="bt-event-msg">{ev.message}</span>
                  </div>
                  <div className="bt-event-meta">
                    {ev.category} · {ev.source || 'Security Monitor'}{ev.ip ? ` · IP ${ev.ip}` : ''}
                  </div>
                  {ev.details && <div className="bt-event-details">{ev.details}</div>}
                  <div className="bt-event-time">{new Date(ev.timestamp).toLocaleString()}</div>
                </div>
              ))}
            </div>
          </section>
        </div>

        <div className="bt-column">
          <section className="bt-panel">
            <h2>PLANT RECOVERY</h2>
            <p className="bt-panel-note">Restore a halted plant to RUNNING after an incident without waiting for a container restart.</p>
            <div className="bt-plant">
              <div>
                Plant status:{' '}
                <span className={plantStatus === 'RUNNING' ? 'plant-running' : 'plant-halted'}>{plantStatus}</span>
              </div>
              <div className="bt-control-desc">Resetting clears the Modbus HALT coil and resumes telemetry. The action is logged for the SOC.</div>
              <button type="button" className="bt-btn-secondary" onClick={resetPlant}>⟳ RESET PLANT</button>
            </div>
          </section>
        </div>
      </div>
      )}

      <footer className="bt-footer">
        <div>Green Team Training · Defenses auto-reset on logoff / {settings.inactivity_timeout_minutes} min inactivity</div>
        {tab === 'defenses' && (
          <div className="bt-footer-right">
            {applyFlash && <span className={`bt-apply-flash ${applyFlash.includes('FAILED') ? 'err' : ''}`}>{applyFlash}</span>}
            <button type="button" className="bt-apply" onClick={applyDefenses}>APPLY DEFENSES</button>
          </div>
        )}
      </footer>
    </div>
  );
};

export default BlueTeamDashboard;
