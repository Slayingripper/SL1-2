import { useState, useEffect } from 'react';
import './NotificationPopup.css';

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

const NotificationPopup = () => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [shownNotifications, setShownNotifications] = useState<Set<number>>(new Set());

  useEffect(() => {
    // Poll for notifications every 3 seconds
    const checkNotifications = async () => {
      try {
        const response = await fetch('/api/notifications');
        if (!response.ok) return;
        
        const data = await response.json();
        const unreadNotifs = (data.notifications || []).filter((n: Notification) => !n.read);
        
        // Show new unread notifications
        unreadNotifs.forEach((notif: Notification) => {
          if (!shownNotifications.has(notif.id)) {
            setNotifications(prev => [...prev, notif]);
            setShownNotifications(prev => new Set(prev).add(notif.id));
            
            // Auto-dismiss after 30 seconds
            setTimeout(() => {
              closeNotification(notif.id);
            }, 30000);
          }
        });
      } catch (error) {
        console.debug('Failed to fetch notifications:', error);
      }
    };

    checkNotifications();
    const interval = setInterval(checkNotifications, 3000);

    return () => clearInterval(interval);
  }, [shownNotifications]);

  const closeNotification = async (id: number) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
    
    // Mark as read on server
    try {
      await fetch(`/api/notifications/${id}/read`, { method: 'POST' });
    } catch (error) {
      console.debug('Failed to mark notification as read:', error);
    }
  };

  const handleLinkClick = (id: number, link?: string) => {
    if (link) {
      // Replace internal Docker IPs with the hostname user is accessing from
      // This ensures phishing pages work when accessing from external networks (e.g., ZeroTier)
      let externalLink = link;
      try {
        const url = new URL(link);
        // Check if this is an internal Docker IP (172.20.x.x)
        if (url.hostname.startsWith('172.20.')) {
          url.hostname = window.location.hostname;
          externalLink = url.toString();
        }
      } catch (e) {
        console.debug('Failed to parse link URL:', e);
      }
      window.open(externalLink, '_blank');
    }
    closeNotification(id);
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
