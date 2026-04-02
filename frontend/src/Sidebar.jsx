// src/Sidebar.jsx
import { T } from './ui.jsx';

const NAV = [
  { id: 'dashboard', icon: '⬡', label: 'Dashboard' },
  { id: 'clients',   icon: '◈', label: 'Clients & Assets' },
  { id: 'feed',      icon: '◉', label: 'CVE Feed' },
  { id: 'alerts',    icon: '◎', label: 'Alert Queue' },
  { id: 'reports',   icon: '▣', label: 'Reports' },
  { id: 'samples',   icon: '📄', label: 'Sample Reports' },
];

export default function Sidebar({ view, setView, counts, health }) {
  return (
    <div style={{
      width: 232, background: T.sidebar, borderRight: `1px solid ${T.border}`,
      display: 'flex', flexDirection: 'column', height: '100vh',
      position: 'sticky', top: 0, flexShrink: 0,
    }}>
      <div style={{ padding: '22px 20px 18px', borderBottom: `1px solid ${T.border}` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 36, height: 36, background: T.red, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18 }}>🛡</div>
          <div>
            <div style={{ fontFamily: T.head, fontWeight: 800, fontSize: 15, color: T.text }}>CTI Platform</div>
            <div style={{ fontFamily: T.mono, fontSize: 9, color: T.muted, letterSpacing: '.06em' }}>v2.0 · SOC AUTOMATION</div>
          </div>
        </div>
      </div>

      <nav style={{ padding: '12px 10px', flex: 1 }}>
        {NAV.map(n => {
          const active = view === n.id;
          const cnt = counts?.[n.id] || 0;
          return (
            <button key={n.id} onClick={() => setView(n.id)} style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 10,
              padding: '9px 10px', borderRadius: 7, border: 'none', cursor: 'pointer',
              marginBottom: 2, textAlign: 'left',
              background:  active ? 'rgba(220,38,38,.12)' : 'transparent',
              borderLeft: `2px solid ${active ? T.red : 'transparent'}`,
              transition: 'all .12s',
            }}>
              <span style={{ color: active ? T.red : T.muted, fontSize: 14, width: 16, textAlign: 'center', flexShrink: 0 }}>{n.icon}</span>
              <span style={{ fontFamily: T.head, fontSize: 13, fontWeight: active ? 600 : 400, color: active ? T.text : T.subtle, flex: 1 }}>{n.label}</span>
              {cnt > 0 && (
                <span className="pulse" style={{
                  background: T.red, color: '#fff', fontFamily: T.mono,
                  fontSize: 10, fontWeight: 700, padding: '1px 7px', borderRadius: 10, minWidth: 22, textAlign: 'center',
                }}>{cnt}</span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Health indicators */}
      {health && (
        <div style={{ padding: '10px 16px', borderTop: `1px solid ${T.border}`, background: 'rgba(0,0,0,.15)' }}>
          <div style={{ fontFamily: T.mono, fontSize: 9, color: T.muted, letterSpacing: '.08em', marginBottom: 7, textTransform: 'uppercase' }}>Services</div>
          {[['DB', health.db], ['Redis', health.redis], ['ChromaDB', health.chromadb], ['AI Model', health.embedding_model_loaded]].map(([k, ok]) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontFamily: T.mono, fontSize: 10, color: T.muted }}>{k}</span>
              <span style={{ fontFamily: T.mono, fontSize: 10, color: ok ? T.green : T.red, fontWeight: 600 }}>{ok ? '●' : '○'}</span>
            </div>
          ))}
        </div>
      )}

      <div style={{ padding: '12px 20px', borderTop: `1px solid ${T.border}` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className="pulse" style={{ width: 7, height: 7, background: T.green, borderRadius: '50%' }} />
          <span style={{ fontFamily: T.mono, fontSize: 9, color: T.muted, letterSpacing: '.06em' }}>SYSTEM ACTIVE</span>
        </div>
      </div>
    </div>
  );
}
