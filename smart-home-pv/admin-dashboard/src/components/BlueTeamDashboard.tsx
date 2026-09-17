import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
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

interface SecurityEvent {
  timestamp: string;
  severity: string;
  category: string;
  message: string;
  details?: string;
  source?: string;
  ip?: string;
}

interface OperatorUser {
  username: string;
  role: string;
  description: string;
}

interface UserTicket {
  id: number;
  created: string;
  subject: string;
  description: string;
  reporter: string;
  source: 'user' | 'security_monitor';
  category?: string | null;
  ip?: string | null;
  status: 'open' | 'investigating' | 'resolved' | 'closed';
}

const TICKET_STATUS_FLOW: UserTicket['status'][] = ['open', 'investigating', 'resolved', 'closed'];

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

const severityClass = (sev?: string | null) => {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'sev-critical';
  if (s === 'high') return 'sev-high';
  if (s === 'medium') return 'sev-medium';
  return 'sev-low';
};

/* ── Reusable pieces ─────────────────────────────────────── */

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

/** Collapsible section used to structure every tab */
const Section: React.FC<{
  title: string;
  subtitle?: string;
  badge?: string;
  badgeTone?: 'ok' | 'warn' | 'off' | 'crit';
  defaultOpen?: boolean;
  children: React.ReactNode;
}> = ({ title, subtitle, badge, badgeTone = 'off', defaultOpen = false, children }) => {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className={`bt-acc ${open ? 'open' : ''}`}>
      <button type="button" className="bt-acc-header" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className="bt-acc-chevron">{open ? '▾' : '▸'}</span>
        <span className="bt-acc-titles">
          <span className="bt-acc-title">{title}</span>
          {subtitle && <span className="bt-acc-sub">{subtitle}</span>}
        </span>
        {badge && <span className={`bt-acc-badge tone-${badgeTone}`}>{badge}</span>}
      </button>
      {open && <div className="bt-acc-body">{children}</div>}
    </section>
  );
};

const UserAccount: React.FC<{
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
    <Section
      title={user.username}
      subtitle={user.description}
      badge={user.role.toUpperCase()}
      badgeTone={user.role === 'blueteam' ? 'ok' : 'warn'}
    >
      <div className="bt-user-form">
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
      </div>
    </Section>
  );
};

/* ── Main console ────────────────────────────────────────── */

const BlueTeamDashboard: React.FC<BlueTeamDashboardProps> = ({ token, onLogout }) => {
  const [settings, setSettings] = useState<DefenseSettings>(DEFAULT_SETTINGS);
  const [defenseActive, setDefenseActive] = useState(false);
  const [controlsEngaged, setControlsEngaged] = useState(0);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [plantStatus, setPlantStatus] = useState('UNKNOWN');
  const [now, setNow] = useState(new Date());
  const [sessionLeft, setSessionLeft] = useState(5 * 60);
  const [applyFlash, setApplyFlash] = useState('');
  const [tab, setTab] = useState<'defenses' | 'users' | 'tickets'>('defenses');
  const [users, setUsers] = useState<OperatorUser[]>([]);
  const [tickets, setTickets] = useState<UserTicket[]>([]);
  const [ticketsLoaded, setTicketsLoaded] = useState(false);

  // Search & filter state
  const [eventQuery, setEventQuery] = useState('');
  const [eventSeverity, setEventSeverity] = useState('all');
  const [eventCategory, setEventCategory] = useState('all');
  const [ticketQuery, setTicketQuery] = useState('');
  const [ticketStatus, setTicketStatus] = useState('all');

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
    if (tab !== 'tickets') return;
    const loadTickets = async () => {
      try {
        const resp = await axios.get('/api/admin/tickets', { headers: authHeaders });
        setTickets((resp.data.tickets || []).filter((t: UserTicket) => t.source === 'user'));
      } catch (err: any) {
        if (err?.response?.status === 401) handleExpired();
      } finally {
        setTicketsLoaded(true);
      }
    };
    loadTickets();
    const iv = setInterval(loadTickets, 10000);
    return () => clearInterval(iv);
  }, [tab]);

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

  const setTicketStatusApi = async (id: number, status: UserTicket['status']) => {
    try {
      await axios.post(`/api/admin/tickets/${id}/status`, { status }, { headers: authHeaders });
      setTickets(prev => prev.map(t => (t.id === id ? { ...t, status } : t)));
    } catch (err: any) {
      if (err?.response?.status === 401) handleExpired();
    }
  };

  /* ── Derived data: search & filters ─────────────────────── */

  const eventCategories = useMemo(
    () => Array.from(new Set(events.map(ev => ev.category).filter(Boolean))).sort(),
    [events]
  );

  const filteredEvents = useMemo(() => events.filter(ev => {
    if (eventSeverity !== 'all' && (ev.severity || '').toLowerCase() !== eventSeverity) return false;
    if (eventCategory !== 'all' && ev.category !== eventCategory) return false;
    const q = eventQuery.trim().toLowerCase();
    if (q) {
      const blob = `${ev.message} ${ev.details || ''} ${ev.category} ${ev.source || ''} ${ev.ip || ''}`.toLowerCase();
      if (!blob.includes(q)) return false;
    }
    return true;
  }), [events, eventQuery, eventSeverity, eventCategory]);

  const filteredTickets = useMemo(() => tickets.filter(t => {
    if (ticketStatus !== 'all' && t.status !== ticketStatus) return false;
    const q = ticketQuery.trim().toLowerCase();
    if (q) {
      const blob = `${t.subject} ${t.description} ${t.reporter} ${t.ip || ''}`.toLowerCase();
      if (!blob.includes(q)) return false;
    }
    return true;
  }), [tickets, ticketQuery, ticketStatus]);

  const openTickets = tickets.filter(t => t.status === 'open' || t.status === 'investigating').length;

  const fmtClock = now.toLocaleTimeString('en-GB', { hour12: false });
  const fmtDate = now.toLocaleDateString('en-GB', { month: 'short', day: 'numeric', year: 'numeric' }).toUpperCase();
  const sessionMin = String(Math.floor(sessionLeft / 60)).padStart(2, '0');
  const sessionSec = String(sessionLeft % 60).padStart(2, '0');

  const onOff = (on: boolean) => (on ? 'ENABLED' : 'DISABLED');
  const onOffTone = (on: boolean) => (on ? 'ok' : 'off') as 'ok' | 'off';
  const networkEnabled = Number(settings.ip_blacklist_enabled) + Number(settings.ip_whitelist_enabled);

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
        {(['defenses', 'users', 'tickets'] as const).map(t => (
          <button
            key={t}
            type="button"
            className={`bt-tab ${tab === t ? 'active' : ''}`}
            onClick={() => setTab(t)}
          >
            {t.toUpperCase()}
          </button>
        ))}
      </nav>

      {/* ══ DEFENSES ══════════════════════════════════════════ */}
      {tab === 'defenses' && (
        <div className="bt-stack">
          <Section
            title="ACCESS CONTROL & AUTHENTICATION"
            subtitle="Brute-force protection and operator session policy"
            badge={onOff(settings.login_rate_limit)}
            badgeTone={onOffTone(settings.login_rate_limit)}
            defaultOpen
          >
            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">Login Rate Limiting</div>
                  <div className="bt-control-desc">Throttle brute-force attempts on the operator login endpoint. Valid operator credentials are never locked out.</div>
                </div>
                <Toggle checked={settings.login_rate_limit} onChange={v => set('login_rate_limit', v)} />
              </div>
              <label className="bt-field">
                <span>MAX FAILED ATTEMPTS PER MINUTE</span>
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
                  <div className="bt-control-title">Admin Session Timeout</div>
                  <div className="bt-control-desc">Force re-authentication of admin sessions after the configured lifetime.</div>
                </div>
              </div>
              <label className="bt-field">
                <span>SESSION LIFETIME (MINUTES)</span>
                <input
                  type="number" min={1}
                  value={settings.admin_session_timeout_minutes}
                  onChange={e => set('admin_session_timeout_minutes', Number(e.target.value) || 1)}
                />
              </label>
            </div>
          </Section>

          <Section
            title="NETWORK ACCESS CONTROL"
            subtitle="Restrict which source IPs may reach the controller API"
            badge={`${networkEnabled}/2 ENABLED`}
            badgeTone={networkEnabled > 0 ? 'ok' : 'off'}
          >
            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">IP Blocklist</div>
                  <div className="bt-control-desc">Deny requests from known-malicious addresses. Accepts exact IPs, prefixes, or CIDR subnets.</div>
                </div>
                <Toggle checked={settings.ip_blacklist_enabled} onChange={v => set('ip_blacklist_enabled', v)} />
              </div>
              <div className="bt-field">
                <span>BLOCKED IPS / SUBNETS</span>
                <IpListEditor
                  ips={settings.ip_blacklist}
                  placeholder="e.g. 203.0.113.45 or 203.0.113.0/24"
                  onChange={ips => set('ip_blacklist', ips)}
                />
              </div>
            </div>
            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">IP Allowlist</div>
                  <div className="bt-control-desc">When enabled, only the listed addresses may reach the API (default-deny). The login and defense-console endpoints stay reachable as a lockout-recovery path.</div>
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
          </Section>

          <Section
            title="OT PROTOCOL HARDENING"
            subtitle="Industrial protocol defenses for the Modbus/TCP interface"
            badge={onOff(settings.modbus_write_restricted)}
            badgeTone={onOffTone(settings.modbus_write_restricted)}
          >
            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">Modbus Write Protection</div>
                  <div className="bt-control-desc">Block unauthorized HALT coil writes over Modbus TCP, preventing remote shutdown of the plant.</div>
                </div>
                <Toggle checked={settings.modbus_write_restricted} onChange={v => set('modbus_write_restricted', v)} />
              </div>
            </div>
          </Section>

          <Section
            title="TELEMETRY INTEGRITY"
            subtitle="Reject spoofed or physically impossible telemetry"
            badge={onOff(settings.telemetry_validation)}
            badgeTone={onOffTone(settings.telemetry_validation)}
          >
            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">Telemetry Validation</div>
                  <div className="bt-control-desc">Discard telemetry samples outside the physical power bounds below.</div>
                </div>
                <Toggle checked={settings.telemetry_validation} onChange={v => set('telemetry_validation', v)} />
              </div>
              <div className="bt-field-row">
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
            </div>
          </Section>

          <Section
            title="APPLICATION LAYER DEFENSE (WAF)"
            subtitle="Web request filtering for injection attacks"
            badge={onOff(settings.xss_protection)}
            badgeTone={onOffTone(settings.xss_protection)}
          >
            <div className="bt-control">
              <div className="bt-control-head">
                <div>
                  <div className="bt-control-title">XSS / SQLi Signature Filter</div>
                  <div className="bt-control-desc">Block requests carrying script tags, event handlers, or SQL-injection signatures before they reach the application.</div>
                </div>
                <Toggle checked={settings.xss_protection} onChange={v => set('xss_protection', v)} />
              </div>
            </div>
          </Section>

          <Section
            title="ALERTING POLICY"
            subtitle="Which severities raise operator popup notifications"
            badge={settings.alert_notification_tier.toUpperCase()}
            badgeTone="warn"
          >
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
          </Section>

          <Section
            title="INCIDENT RECOVERY"
            subtitle="Restore plant operation after a security incident"
            badge={plantStatus}
            badgeTone={plantStatus === 'RUNNING' ? 'ok' : 'crit'}
          >
            <div className="bt-plant">
              <div>
                Plant status:{' '}
                <span className={plantStatus === 'RUNNING' ? 'plant-running' : 'plant-halted'}>{plantStatus}</span>
              </div>
              <div className="bt-control-desc">Resetting clears the Modbus HALT coil and resumes telemetry without a container restart. The action is logged for the SOC.</div>
              <button type="button" className="bt-btn-secondary" onClick={resetPlant}>⟳ RESET PLANT</button>
            </div>
          </Section>
        </div>
      )}

      {/* ══ USERS ═════════════════════════════════════════════ */}
      {tab === 'users' && (
        <div className="bt-stack">
          <div className="bt-stack-intro">
            <h2>OPERATOR ACCOUNTS</h2>
            <p>Manage credentials for the operator accounts on this controller. Password resets take effect on the account's next login.</p>
          </div>
          {users.length === 0 && <div className="bt-events-empty">Loading operator accounts…</div>}
          {users.map(u => (
            <UserAccount key={u.username} user={u} token={token} onExpired={handleExpired} />
          ))}
        </div>
      )}

      {/* ══ TICKETS ═══════════════════════════════════════════ */}
      {tab === 'tickets' && (
        <div className="bt-stack">
          <Section
            title="TICKET QUEUE"
            subtitle="Support tickets submitted by users — triage and update status"
            badge={`${openTickets} OPEN`}
            badgeTone={openTickets > 0 ? 'warn' : 'ok'}
            defaultOpen
          >
            <div className="bt-toolbar">
              <input
                className="bt-search"
                placeholder="Search subject, description, reporter, IP…"
                value={ticketQuery}
                onChange={e => setTicketQuery(e.target.value)}
              />
              <select value={ticketStatus} onChange={e => setTicketStatus(e.target.value)}>
                <option value="all">All statuses</option>
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
                <option value="closed">Closed</option>
              </select>
            </div>
            <div className="bt-tickets-list">
              {!ticketsLoaded && <div className="bt-events-empty">Loading tickets…</div>}
              {ticketsLoaded && filteredTickets.length === 0 && (
                <div className="bt-events-empty">No tickets match the current search / filter.</div>
              )}
              {filteredTickets.map(t => (
                <div key={t.id} className={`bt-ticket status-${t.status}`}>
                  <div className="bt-ticket-top">
                    <span className="bt-ticket-id">#{t.id}</span>
                    <span className="bt-ticket-subject">{t.subject}</span>
                    <span className={`bt-ticket-status st-${t.status}`}>{t.status.toUpperCase()}</span>
                  </div>
                  <div className="bt-ticket-desc">{t.description}</div>
                  <div className="bt-event-meta">
                    From {t.reporter}
                    {t.ip ? ` · IP ${t.ip}` : ''}
                    {t.category ? ` · ${t.category}` : ''}
                    {' · '}{new Date(t.created).toLocaleString()}
                  </div>
                  <div className="bt-ticket-actions">
                    {TICKET_STATUS_FLOW.filter(s => s !== t.status).map(s => (
                      <button
                        key={s}
                        type="button"
                        className="bt-ticket-action"
                        onClick={() => setTicketStatusApi(t.id, s)}
                      >
                        {s === 'open' ? 'REOPEN' : s.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </Section>

          <Section
            title="SECURITY EVENT REVIEW"
            subtitle="Incidents and suspicious behavior logged by the SOC"
            badge={`${events.length} EVENTS`}
            badgeTone={events.some(ev => ['critical', 'high'].includes((ev.severity || '').toLowerCase())) ? 'crit' : 'off'}
            defaultOpen
          >
            <div className="bt-toolbar">
              <input
                className="bt-search"
                placeholder="Search message, details, source, IP…"
                value={eventQuery}
                onChange={e => setEventQuery(e.target.value)}
              />
              <select value={eventSeverity} onChange={e => setEventSeverity(e.target.value)}>
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select value={eventCategory} onChange={e => setEventCategory(e.target.value)}>
                <option value="all">All categories</option>
                {eventCategories.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div className="bt-result-count">
              Showing {filteredEvents.length} of {events.length} events
            </div>
            <div className="bt-events">
              {filteredEvents.length === 0 && <div className="bt-events-empty">No events match the current search / filter.</div>}
              {filteredEvents.map((ev, i) => (
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
          </Section>
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
