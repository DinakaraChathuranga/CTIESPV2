// src/App.jsx
import { useState, useEffect, useCallback } from 'react';
import Sidebar from './Sidebar.jsx';
import { T, useToast } from './ui.jsx';
import { Dashboard, Clients, Feed, Alerts, Reports, SampleReports } from './views.jsx';
import { systemAPI, alertsAPI } from './api.js';

export default function App() {
  const [view, setView]     = useState('dashboard');
  const [health, setHealth] = useState(null);
  const [counts, setCounts] = useState({});
  const { toast, ToastContainer } = useToast();

  const refreshHealth = useCallback(async () => {
    try {
      const [h, stats] = await Promise.all([systemAPI.health(), systemAPI.stats()]);
      setHealth(h);
      setCounts(c => ({ ...c, alerts: stats.alerts_pending }));
    } catch {}
  }, []);

  useEffect(() => {
    refreshHealth();
    const t = setInterval(refreshHealth, 25000);
    return () => clearInterval(t);
  }, []);

  const handleCountChange = (key, val) => setCounts(c => ({ ...c, [key]: val }));

  const views = {
    dashboard: <Dashboard setView={setView} />,
    clients:   <Clients toast={toast} />,
    feed:      <Feed toast={toast} />,
    alerts:    <Alerts toast={toast} onCountChange={handleCountChange} />,
    reports:   <Reports toast={toast} />,
    samples:   <SampleReports toast={toast} />,
  };

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: T.bg }}>
      <Sidebar view={view} setView={setView} counts={counts} health={health} />
      <main style={{ flex: 1, overflowY: 'auto', minHeight: '100vh' }}>
        {views[view] || views.dashboard}
      </main>
      {ToastContainer}
    </div>
  );
}
