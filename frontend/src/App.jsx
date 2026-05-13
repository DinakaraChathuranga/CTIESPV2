// src/App.jsx
import { useState, useEffect, useCallback } from 'react';
import Sidebar from './Sidebar.jsx';
import Login from './Login.jsx';
import { T, useToast } from './ui.jsx';
import { Dashboard, Clients, Feed, Alerts, Reports, SampleReports, Users } from './views.jsx';
import { systemAPI, alertsAPI, authAPI } from './api.js';

export default function App() {
  const [user, setUser]     = useState(null);   // null = not logged in / checking
  const [ready, setReady]   = useState(false);  // finished auth check
  const [view, setView]     = useState('dashboard');
  const [health, setHealth] = useState(null);
  const [counts, setCounts] = useState({});
  const { toast, ToastContainer } = useToast();

  // ── Auth bootstrap ─────────────────────────────────────────────────────────
  useEffect(() => {
    const token = localStorage.getItem('cti_token');
    const stored = localStorage.getItem('cti_user');
    if (!token) { setReady(true); return; }

    // Validate token by calling /me
    authAPI.me()
      .then(u => { setUser(u); setReady(true); })
      .catch(() => {
        localStorage.removeItem('cti_token');
        localStorage.removeItem('cti_user');
        setReady(true);
      });
  }, []);

  const handleLogin = (u) => setUser(u);

  const handleLogout = () => {
    localStorage.removeItem('cti_token');
    localStorage.removeItem('cti_user');
    setUser(null);
  };

  // ── Health polling (only when logged in) ──────────────────────────────────
  const refreshHealth = useCallback(async () => {
    if (!user) return;
    try {
      const [h, stats] = await Promise.all([systemAPI.health(), systemAPI.stats()]);
      setHealth(h);
      setCounts(c => ({ ...c, alerts: stats.alerts_pending }));
    } catch {}
  }, [user]);

  useEffect(() => {
    if (!user) return;
    refreshHealth();
    const t = setInterval(refreshHealth, 25000);
    return () => clearInterval(t);
  }, [user, refreshHealth]);

  const handleCountChange = (key, val) => setCounts(c => ({ ...c, [key]: val }));

  // ── Render ─────────────────────────────────────────────────────────────────
  if (!ready) {
    return (
      <div style={{ minHeight: '100vh', background: '#0d0d1a', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ color: '#6b7280', fontFamily: 'Inter, sans-serif', fontSize: 14 }}>Loading…</div>
      </div>
    );
  }

  if (!user) {
    return <Login onLogin={handleLogin} />;
  }

  const isAdmin = user.role === 'security_admin';

  const views = {
    dashboard: <Dashboard setView={setView} user={user} />,
    clients:   <Clients toast={toast} user={user} isAdmin={isAdmin} />,
    feed:      <Feed toast={toast} user={user} isAdmin={isAdmin} />,
    alerts:    <Alerts toast={toast} onCountChange={handleCountChange} user={user} />,
    reports:   <Reports toast={toast} user={user} />,
    samples:   <SampleReports toast={toast} isAdmin={isAdmin} />,
    users:     isAdmin ? <Users toast={toast} user={user} /> : null,
  };

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: T.bg }}>
      <Sidebar
        view={view}
        setView={setView}
        counts={counts}
        health={health}
        user={user}
        isAdmin={isAdmin}
        onLogout={handleLogout}
      />
      <main style={{ flex: 1, overflowY: 'auto', minHeight: '100vh' }}>
        {views[view] || views.dashboard}
      </main>
      {ToastContainer}
    </div>
  );
}
