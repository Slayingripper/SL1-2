import { useState, useEffect, useRef, useCallback } from 'react';
import './NotificationPopup.css';
import { logAdminActivity } from '../utils/activityLogger';

interface Notification {
  id: number;
  timestamp: string;
  type: string;
  title: string;
  message: string;
  link?: string;
  link_text?: string;
  read: boolean;
}

const AUTO_DISMISS_MS = 20000;

// Blue-team alert tier controls which severities produce real-time popups.
const TIER_RANK: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

const NotificationPopup = () => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  // Track handled ids in a ref so polling, rendering and auto-dismiss timers
  // never fight over duplicates
  const handledIds = useRef<Set<number>>(new Set());
  const closingIds = useRef<Set<number>>(new Set());
  const tierRef = useRef<string>('low'); // 'low' = show everything

  useEffect(() => {
    let alive = true;
    const loadTier = async () => {
      try {
        const resp = await fetch('/api/blueteam/defense_status');
        if (!resp.ok) return;
        const data = await resp.json();
        if (alive && data?.alert_tier) tierRef.current = data.alert_tier;
      } catch (e) {
        /* ignore */
      }
    };
    loadTier();
    const t = setInterval(loadTier, 15000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const closeNotification = useCallback(async (id: number) => {
    if (closingIds.current.has(id)) return; // idempotent close
    closingIds.current.add(id);
    setNotifications(prev => prev.filter(n => n.id !== id));
    void logAdminActivity({
      action: 'notification_closed',
      eventType: 'notification',
      page: 'dashboard/notifications',
      target: 'notification-popup',
      details: {
        notification_id: id,
      },
    });

    // Mark as read on server (best effort - a trimmed notification may 404)
    try {
      await fetch(`/api/notifications/${id}/read`, { method: 'POST' });
    } catch (error) {
      console.debug('Failed to mark notification as read:', error);
    }
  }, []);

  useEffect(() => {
    let timer: number | undefined;
    const checkNotifications = async () => {
      // Pause polling while the tab is hidden to save CPU/network
      if (document.hidden) return;
      try {
        const response = await fetch('/api/notifications');
        if (!response.ok) return;

        const data = await response.json();
        const threshold = TIER_RANK[tierRef.current] ?? 0;
        const unreadNotifs = (data.notifications || []).filter((n: Notification) => {
          if (n.read || handledIds.current.has(n.id)) return false;
          // Respect blue-team notification tier (drop low-priority popups)
          const typeKey = (n.type || 'low').toLowerCase();
          const rank = TIER_RANK[typeKey];
          if (rank !== undefined && rank < threshold) return false;
          return true;
        });

        for (const notif of unreadNotifs) {
          handledIds.current.add(notif.id);
          setNotifications(prev =>
            prev.some(p => p.id === notif.id) ? prev : [...prev, notif]
          );
          window.setTimeout(() => {
            void closeNotification(notif.id);
          }, AUTO_DISMISS_MS);
        }
      } catch (error) {
        console.debug('Failed to fetch notifications:', error);
      }
    };

    checkNotifications();
    timer = window.setInterval(checkNotifications, 8000);

    return () => clearInterval(timer);
  }, [closeNotification]);

  const handleLinkClick = (id: number, link?: string) => {
    let externalLink = link || '';
    if (link) {
      // Replace internal Docker IPs with the hostname user is accessing from
      // This ensures phishing pages work when accessing from external networks (e.g., ZeroTier)
      try {
        const url = new URL(link);
        // Check if this is an internal Docker IP (172.20.x.x)
        if (url.hostname.startsWith('172.20.')) {
          url.hostname = window.location.hostname;
          url.protocol = window.location.protocol;
          externalLink = url.toString();
        }
      } catch (e) {
        console.debug('Failed to parse link URL:', e);
      }
      window.open(externalLink, '_blank');
    }
    void logAdminActivity({
      action: 'notification_link_opened',
      eventType: 'notification',
      page: 'dashboard/notifications',
      target: 'notification-link',
      details: {
        notification_id: id,
        destination: externalLink,
      },
    });
    void closeNotification(id);
  };

  return (
    <div className="notification-container">
      {notifications.map(notif => (
        <div key={notif.id} className={`notification-popup ${notif.type}`}>
          <div className="notification-header">
            <span className="notification-icon">⚠️</span>
            <span className="notification-title">{notif.title}</span>
            <button
              className="notification-close"
              onClick={() => closeNotification(notif.id)}
            >
              ×
            </button>
          </div>
          <div className="notification-body">
            <p>{notif.message}</p>
            {notif.link && (
              <button
                className="notification-link"
                onClick={() => handleLinkClick(notif.id, notif.link)}
              >
                {notif.link_text || 'Click here'}
              </button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};

export default NotificationPopup;
