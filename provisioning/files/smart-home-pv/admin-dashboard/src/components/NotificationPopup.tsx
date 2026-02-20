import { useState, useEffect, useRef } from 'react';
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
        
        // Use ref for the check to avoid dependency on state
        const shownIds = shownIdsRef.current;
        const idsToShow = new Set<number>();
        
        unreadNotifs.forEach((notif: Notification) => {
          if (!shownIds.has(notif.id)) {
            idsToShow.add(notif.id);
          }
        });

        if (idsToShow.size > 0) {
          // Use functional updates to ensure we're adding to the latest state, 
          // even if this callback runs slightly delayed
          setNotifications(prev => {
             // We can't use functional update with shownNotifications from closure unless we pass it
             // But here we're filtering unreadNotifs which is fresh from API call.
             // The only issue is duplicated if state update race condition.
             return [...prev, ...unreadNotifs.filter((n: Notification) => idsToShow.has(n.id))];
          });
          
          setShownNotifications(prev => {
            const next = new Set(prev);
            idsToShow.forEach(id => next.add(id));
            return next;
          });

          // Auto-dismiss logic for the new ones
          unreadNotifs
            .filter((n: Notification) => idsToShow.has(n.id))
            .forEach((notif: Notification) => {
               setTimeout(() => closeNotification(notif.id), 30000);
            });
        }
      } catch (error) {
        console.debug('Failed to fetch notifications:', error);
      }
    };

    checkNotifications(); // Initial fetch
    const interval = setInterval(checkNotifications, 3000);

    return () => clearInterval(interval);
  }, []); // Run ONCE on mount

  // Sync state to ref for effect to use fresh values without re-running
  const shownIdsRef = useRef(new Set<number>());
  useEffect(() => {
    shownIdsRef.current = shownNotifications;
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
