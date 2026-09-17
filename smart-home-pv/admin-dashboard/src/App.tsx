import { useState, useEffect } from 'react';
import axios from 'axios';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import BlueTeamDashboard from './components/BlueTeamDashboard';
import './App.css';

function App() {
  const [token, setToken] = useState<string | null>(null);
  const [role, setRole] = useState<'admin' | 'blueteam' | null>(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    // Restore a saved session, but verify it against the server first. Tokens
    // live in memory on the controller, so after a restart (or timeout) the
    // stored token is stale — validating avoids rendering a dashboard that
    // only produces 401/403 errors.
    const savedToken = localStorage.getItem('pv_admin_token');
    const savedRole = (localStorage.getItem('pv_admin_role') as 'admin' | 'blueteam' | null) || 'admin';

    if (!savedToken) {
      setChecking(false);
      return;
    }

    let alive = true;
    (async () => {
      const headers = { Authorization: `Bearer ${savedToken}` };
      try {
        if (savedRole === 'blueteam') {
          await axios.get('/api/blueteam/settings', { headers });
        } else {
          await axios.get('/api/admin/security/events', { headers });
        }
        if (!alive) return;
        setToken(savedToken);
        setRole(savedRole);
      } catch {
        if (!alive) return;
        localStorage.removeItem('pv_admin_token');
        localStorage.removeItem('pv_admin_role');
      } finally {
        if (alive) setChecking(false);
      }
    })();

    return () => { alive = false; };
  }, []);

  const handleLoginSuccess = (newToken: string, newRole?: 'admin' | 'blueteam') => {
    setToken(newToken);
    setRole(newRole || 'admin');
    localStorage.setItem('pv_admin_token', newToken);
    localStorage.setItem('pv_admin_role', newRole || 'admin');
  };

  const handleLogout = () => {
    setToken(null);
    setRole(null);
    localStorage.removeItem('pv_admin_token');
    localStorage.removeItem('pv_admin_role');
  };

  if (checking) {
    return <div className="App" />;
  }

  return (
    <div className="App">
      {token ? (
        role === 'blueteam' ? (
          <BlueTeamDashboard token={token} onLogout={handleLogout} />
        ) : (
          <Dashboard token={token} onLogout={handleLogout} />
        )
      ) : (
        <Login onLoginSuccess={handleLoginSuccess} />
      )}
    </div>
  );
}

export default App;
