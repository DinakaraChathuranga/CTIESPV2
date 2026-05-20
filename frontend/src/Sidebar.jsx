// src/Sidebar.jsx
import { useState } from 'react';
import { T } from './ui.jsx';

const NAV_BASE = [
  { id: 'dashboard', icon: '⬡', label: 'Dashboard' },
  { id: 'clients',   icon: '◈', label: 'Clients & Assets' },
  { id: 'feed',      icon: '◉', label: 'CVE Feed' },
  { id: 'alerts',    icon: '◎', label: 'Alert Queue' },
  { id: 'reports',   icon: '▣', label: 'Reports' },
  { id: 'samples',   icon: '📄', label: 'Sample Reports' },
];

const NAV_ADMIN = { id: 'users', icon: '👥', label: 'Users' };

export default function Sidebar({ view, setView, counts, health, user, isAdmin, onLogout }) {
  const nav = isAdmin ? [...NAV_BASE, NAV_ADMIN] : NAV_BASE;
  const [healthHovered, setHealthHovered] = useState(false);

  const allHealthy = health && Object.values({
    db: health.db,
    redis: health.redis,
    model: health.embedding_model_loaded,
  }).every(Boolean);

  const healthItems = [
    ['DB', health?.db],
    ['Redis', health?.redis],
    ['AI Model', health?.embedding_model_loaded],
  ];

  return (
    <div style={{
      width: 232, background: T.sidebar, borderRight: `1px solid ${T.border}`,
      display: 'flex', flexDirection: 'column', height: '100vh',
      position: 'sticky', top: 0, flexShrink: 0,
    }}>
      {/* Logo */}
      <div style={{ padding: '22px 20px 18px', borderBottom: `1px solid ${T.border}` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 36, height: 36, background: T.red, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18 }}>🛡</div>
          <div>
            <div style={{ fontFamily: T.head, fontWeight: 800, fontSize: 15, color: T.text }}>CTI Platform</div>
            <div style={{ fontFamily: T.mono, fontSize: 9, color: T.muted, letterSpacing: '.06em' }}>v2.0 · SOC AUTOMATION</div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ padding: '12px 10px', flex: 1 }}>
        {nav.map((n, idx) => {
          const active = view === n.id;
          const pendingAlerts = counts?.alerts || 0;
          const draftReports = counts?.reports || 0;

          const subCount = n.id === 'alerts' ? pendingAlerts
            : n.id === 'reports' ? draftReports
            : 0;

          const showSep = idx === 3; // separator before Reports group

          return (
            <div key={n.id}>
              {showSep && (
                <div style={{ height: 1, background: T.border, margin: '6px 4px 8px', opacity: 0.5 }} />
              )}
              <button onClick={() => setView(n.id)} style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                padding: '9px 10px', borderRadius: 7, border: 'none', cursor: 'pointer',
                marginBottom: 2, textAlign: 'left',
                background: active ? 'rgba(220,38,38,.12)' : 'transparent',
                borderLeft: `2px solid ${active ? T.red : 'transparent'}`,
                transition: 'all .12s',
              }}>
                <span style={{ color: active ? T.red : T.muted, fontSize: 14, width: 16, textAlign: 'center', flexShrink: 0 }}>{n.icon}</span>
                <span style={{ fontFamily: T.head, fontSize: 13, fontWeight: active ? 600 : 400, color: active ? T.text : T.subtle, flex: 1, textAlign: 'left' }}>{n.label}
                  {subCount > 0 && (
                    <div style={{ fontFamily: T.mono, fontSize: 9, color: n.id === 'alerts' ? T.orange : T.blue, marginTop: 1 }}>
                      {n.id === 'alerts' ? `${subCount} pending` : `${subCount} draft`}
                    </div>
                  )}
                </span>
                {n.id === 'alerts' && pendingAlerts > 0 && (
                  <span className="pulse" style={{
                    background: T.red, color: '#fff', fontFamily: T.mono,
                    fontSize: 10, fontWeight: 700, padding: '1px 7px', borderRadius: 10,
                    minWidth: 22, textAlign: 'center',
                  }}>{pendingAlerts}</span>
                )}
              </button>
            </div>
          );
        })}
      </nav>

      {/* Health indicators */}
      {health && (
        <div
          onMouseEnter={() => setHealthHovered(true)}
          onMouseLeave={() => setHealthHovered(false)}
          style={{ padding: '10px 16px', borderTop: `1px solid ${T.border}`, background: 'rgba(0,0,0,.15)', cursor: 'default', transition: 'all .15s' }}
        >
          {!healthHovered ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ display: 'flex', gap: 5 }}>
                {healthItems.map(([k, ok]) => (
                  <div key={k} style={{ width: 7, height: 7, borderRadius: '50%', background: ok ? T.green : T.red }} />
                ))}
              </div>
              <span style={{ fontFamily: T.mono, fontSize: 9, color: allHealthy ? T.green : T.orange }}>
                {allHealthy ? 'All systems operational' : 'Service degraded'}
              </span>
            </div>
          ) : (
            <div>
              <div style={{ fontFamily: T.mono, fontSize: 9, color: T.muted, letterSpacing: '.08em', marginBottom: 7, textTransform: 'uppercase' }}>Services</div>
              {healthItems.map(([k, ok]) => (
                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ fontFamily: T.mono, fontSize: 10, color: T.muted }}>{k}</span>
                  <span style={{ fontFamily: T.mono, fontSize: 10, color: ok ? T.green : T.red, fontWeight: 600 }}>{ok ? '● online' : '○ offline'}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* User info + logout */}
      <div style={{ padding: '12px 14px', borderTop: `1px solid ${T.border}` }}>
        {user && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <div style={{
              width: 28, height: 28, borderRadius: 6,
              background: user.role === 'security_admin' ? 'rgba(220,38,38,.2)' : 'rgba(37,99,235,.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontFamily: T.head, fontWeight: 800, fontSize: 13,
              color: user.role === 'security_admin' ? T.red : T.blue,
              flexShrink: 0,
            }}>
              {user.username[0].toUpperCase()}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontFamily: T.head, fontSize: 12, fontWeight: 600, color: T.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {user.username}
              </div>
              <div style={{ fontFamily: T.mono, fontSize: 9, color: user.role === 'security_admin' ? T.red : T.blue, textTransform: 'uppercase', letterSpacing: '.05em' }}>
                {user.role === 'security_admin' ? 'Admin' : 'Reader'}
              </div>
            </div>
          </div>
        )}
        <button onClick={onLogout} style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 8,
          padding: '7px 10px', borderRadius: 6, border: `1px solid ${T.border}`,
          background: 'transparent', color: T.muted, cursor: 'pointer',
          fontFamily: T.head, fontSize: 12, transition: 'all .12s',
        }}
          onMouseEnter={e => { e.currentTarget.style.background = 'rgba(220,38,38,.1)'; e.currentTarget.style.color = T.red; e.currentTarget.style.borderColor = T.red + '44'; }}
          onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = T.muted; e.currentTarget.style.borderColor = T.border; }}
        >
          <span style={{ fontSize: 12 }}>⏻</span> Sign Out
        </button>
      </div>
    </div>
  );
}
