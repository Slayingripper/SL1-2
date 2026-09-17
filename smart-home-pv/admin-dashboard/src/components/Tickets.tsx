import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import './Tickets.css';

interface TicketsProps {
  token: string;
}

interface Ticket {
  id: number;
  created: string;
  subject: string;
  description: string;
  reporter: string;
  source: 'user' | 'security_monitor';
  severity?: string | null;
  category?: string | null;
  ip?: string | null;
  status: 'open' | 'investigating' | 'resolved' | 'closed';
  count: number;
  last_seen: string;
}

type Filter = 'all' | 'user' | 'security_monitor' | 'open';

const STATUS_FLOW: Ticket['status'][] = ['open', 'investigating', 'resolved', 'closed'];

const Tickets: React.FC<TicketsProps> = ({ token }) => {
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [filter, setFilter] = useState<Filter>('all');
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState('');

  const authHeaders = { Authorization: `Bearer ${token}` };

  const load = useCallback(async () => {
    try {
      const resp = await axios.get('/api/admin/tickets', { headers: authHeaders });
      setTickets(resp.data.tickets || []);
      setError('');
    } catch {
      setError('Failed to load tickets');
    } finally {
      setLoaded(true);
    }
  }, [token]);

  useEffect(() => {
    load();
    const iv = setInterval(load, 10000);
    return () => clearInterval(iv);
  }, [load]);

  const setStatus = async (id: number, status: Ticket['status']) => {
    try {
      await axios.post(`/api/admin/tickets/${id}/status`, { status }, { headers: authHeaders });
      setTickets(prev => prev.map(t => (t.id === id ? { ...t, status } : t)));
    } catch {
      setError('Failed to update ticket status');
    }
  };

  const visible = tickets.filter(t => {
    if (filter === 'all') return true;
    if (filter === 'open') return t.status === 'open' || t.status === 'investigating';
    return t.source === filter;
  });

  const counts = {
    all: tickets.length,
    user: tickets.filter(t => t.source === 'user').length,
    security_monitor: tickets.filter(t => t.source === 'security_monitor').length,
    open: tickets.filter(t => t.status === 'open' || t.status === 'investigating').length,
  };

  const sevClass = (sev?: string | null) => {
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return 'tk-sev-critical';
    if (s === 'high') return 'tk-sev-high';
    if (s === 'medium') return 'tk-sev-medium';
    return 'tk-sev-low';
  };

  return (
    <div className="tickets-view">
      <div className="tickets-head">
        <div>
          <h2 className="tickets-title">Tickets</h2>
          <p className="tickets-sub">
            User-submitted support requests and incidents auto-raised from suspicious activity
          </p>
        </div>
        <div className="tickets-filters">
          {([
            ['all', `All (${counts.all})`],
            ['open', `Needs attention (${counts.open})`],
            ['user', `User submitted (${counts.user})`],
            ['security_monitor', `Security incidents (${counts.security_monitor})`],
          ] as [Filter, string][]).map(([key, label]) => (
            <button
              key={key}
              className={`tk-filter ${filter === key ? 'active' : ''}`}
              onClick={() => setFilter(key)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {error && <div className="tk-error">{error}</div>}

      <div className="tickets-list">
        {!loaded && <div className="tk-empty">Loading tickets…</div>}
        {loaded && visible.length === 0 && (
          <div className="tk-empty">No tickets in this view.</div>
        )}
        {visible.map(t => (
          <div key={t.id} className={`tk-card ${t.status}`}>
            <div className="tk-card-main">
              <div className="tk-card-top">
                <span className="tk-id">#{t.id}</span>
                {t.source === 'security_monitor' ? (
                  <span className={`tk-source tk-source-sec ${sevClass(t.severity)}`}>
                    ⚠ SECURITY INCIDENT{t.severity ? ` · ${t.severity.toUpperCase()}` : ''}
                  </span>
                ) : (
                  <span className="tk-source tk-source-user">USER TICKET</span>
                )}
                {t.count > 1 && <span className="tk-count">×{t.count} occurrences</span>}
                <span className={`tk-status tk-status-${t.status}`}>{t.status.toUpperCase()}</span>
              </div>
              <div className="tk-subject">{t.subject}</div>
              <div className="tk-desc">{t.description}</div>
              <div className="tk-meta">
                <span>From: <b>{t.reporter}</b></span>
                {t.category && <span>Category: {t.category}</span>}
                {t.ip && <span>IP: {t.ip}</span>}
                <span>Created: {new Date(t.created).toLocaleString()}</span>
                {t.count > 1 && <span>Last seen: {new Date(t.last_seen).toLocaleString()}</span>}
              </div>
            </div>
            <div className="tk-actions">
              {STATUS_FLOW.filter(s => s !== t.status).map(s => (
                <button key={s} className={`tk-action tk-action-${s}`} onClick={() => setStatus(t.id, s)}>
                  {s === 'open' ? 'Reopen' : s.charAt(0).toUpperCase() + s.slice(1)}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Tickets;
