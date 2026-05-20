// src/ui.jsx — complete design system
import { useState, useRef, useEffect } from 'react';

export const T = {
  bg: '#080c14', sidebar: '#0d1117', card: '#111827',
  border: '#1f2937', surface: '#1a2235',
  red: '#dc2626', redDim: '#7f1d1d', redGlow: 'rgba(220,38,38,.13)',
  orange: '#ea580c', orangeDim: '#7c2d12',
  yellow: '#d97706', yellowDim: '#713f12',
  green: '#16a34a', greenDim: '#14532d',
  blue: '#2563eb', blueDim: '#1e3a8a',
  teal: '#0d9488', tealDim: '#134e4a',
  text: '#f1f5f9', muted: '#64748b', subtle: '#94a3b8',
  head: "'Outfit', sans-serif",
  mono: "'JetBrains Mono', monospace",
};

export const SEV = {
  CRITICAL: { fg: '#dc2626', bg: '#7f1d1d' },
  HIGH:     { fg: '#ea580c', bg: '#7c2d12' },
  MEDIUM:   { fg: '#d97706', bg: '#713f12' },
  LOW:      { fg: '#16a34a', bg: '#14532d' },
};

export function sevStyle(s = 'MEDIUM') {
  const k = (s || '').toUpperCase();
  const c = SEV[k] || SEV.MEDIUM;
  return { color: c.fg, background: c.bg, border: `1px solid ${c.fg}44` };
}

export const Badge = ({ sev, label, style = {} }) => (
  <span style={{
    ...sevStyle(sev), fontFamily: T.mono, fontSize: 10, fontWeight: 600,
    padding: '2px 8px', borderRadius: 4, letterSpacing: '.08em',
    textTransform: 'uppercase', display: 'inline-block', whiteSpace: 'nowrap', ...style,
  }}>{label || sev}</span>
);

export const PriorityBar = ({ score }) => {
  if (!score) return null;
  const pct = Math.min(100, score);
  const color = score >= 75 ? T.red : score >= 50 ? T.orange : score >= 25 ? T.yellow : T.green;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 4, background: T.border, borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2, transition: 'width .3s' }} />
      </div>
      <span style={{ fontFamily: T.mono, fontSize: 10, color, minWidth: 26, textAlign: 'right' }}>{Math.round(pct)}</span>
    </div>
  );
};

export const Spinner = ({ size = 16 }) => (
  <span className="spin" style={{
    display: 'inline-block', width: size, height: size, flexShrink: 0,
    border: `2px solid ${T.border}`, borderTopColor: T.red, borderRadius: '50%',
  }} />
);

const BV = {
  primary: { bg: T.red,     fg: '#fff', bd: 'none' },
  ghost:   { bg: 'transparent', fg: T.subtle, bd: `1px solid ${T.border}` },
  success: { bg: T.green,   fg: '#fff', bd: 'none' },
  danger:  { bg: T.redDim,  fg: T.red,  bd: `1px solid ${T.red}44` },
  blue:    { bg: T.blue,    fg: '#fff', bd: 'none' },
  orange:  { bg: T.orangeDim, fg: T.orange, bd: `1px solid ${T.orange}44` },
  teal:    { bg: T.tealDim, fg: T.teal, bd: `1px solid ${T.teal}44` },
};

export const Btn = ({ variant = 'ghost', onClick, children, disabled, loading, style = {}, sm }) => {
  const v = BV[variant] || BV.ghost;
  return (
    <button onClick={onClick} disabled={disabled || loading} style={{
      background: v.bg, color: v.fg, border: v.bd,
      fontFamily: T.head, fontWeight: 500, fontSize: sm ? 12 : 13,
      padding: sm ? '5px 11px' : '7px 14px', borderRadius: 6,
      cursor: (disabled || loading) ? 'not-allowed' : 'pointer',
      opacity: (disabled || loading) ? .5 : 1,
      display: 'inline-flex', alignItems: 'center', gap: 6,
      transition: 'opacity .12s', whiteSpace: 'nowrap', ...style,
    }}>
      {loading && <Spinner size={13} />}
      {children}
    </button>
  );
};

export const Card = ({ children, style = {}, glow, onClick, onMouseEnter, onMouseLeave }) => (
  <div onClick={onClick} onMouseEnter={onMouseEnter} onMouseLeave={onMouseLeave} style={{
    background: T.card, border: `1px solid ${T.border}`, borderRadius: 10, padding: 20,
    boxShadow: glow ? `0 0 22px ${glow}` : 'none', cursor: onClick ? 'pointer' : 'default',
    transition: 'box-shadow .2s', ...style,
  }}>{children}</div>
);

export const Inp = ({ value, onChange, placeholder, type = 'text', style = {}, onKeyDown }) => (
  <input type={type} value={value} onChange={onChange} placeholder={placeholder} onKeyDown={onKeyDown} style={{
    background: T.surface, border: `1px solid ${T.border}`, borderRadius: 6,
    padding: '8px 12px', color: T.text, fontFamily: T.head, fontSize: 13, width: '100%', ...style,
  }} />
);

export const Sel = ({ value, onChange, children, style = {} }) => (
  <select value={value} onChange={onChange} style={{
    background: T.surface, border: `1px solid ${T.border}`, borderRadius: 6,
    padding: '8px 12px', color: T.text, fontFamily: T.head, fontSize: 13, width: '100%', ...style,
  }}>{children}</select>
);

export const Textarea = ({ value, onChange, placeholder, rows = 3, style = {} }) => (
  <textarea value={value} onChange={onChange} placeholder={placeholder} rows={rows} style={{
    background: T.surface, border: `1px solid ${T.border}`, borderRadius: 6,
    padding: '8px 12px', color: T.text, fontFamily: T.head, fontSize: 12.5,
    width: '100%', resize: 'vertical', ...style,
  }} />
);

export const Lbl = ({ children }) => (
  <div style={{ fontFamily: T.head, fontSize: 11, color: T.muted, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 6 }}>{children}</div>
);

export const Modal = ({ children, onClose, width = 520, title }) => (
  <div className="fade-in" onClick={onClose} style={{
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,.82)',
    zIndex: 500, display: 'flex', alignItems: 'flex-start', justifyContent: 'center',
    overflowY: 'auto', padding: '32px 16px',
  }}>
    <div onClick={e => e.stopPropagation()} style={{
      background: T.card, border: `1px solid ${T.border}`, borderRadius: 12,
      padding: 28, width, maxWidth: '96vw', boxShadow: '0 25px 60px rgba(0,0,0,.7)',
    }}>
      {title && <div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 16, color: T.text, marginBottom: 20 }}>{title}</div>}
      {children}
    </div>
  </div>
);

export const SectionHead = ({ title, sub, action }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
    <div>
      <h1 style={{ fontFamily: T.head, fontSize: 22, fontWeight: 800, color: T.text }}>{title}</h1>
      {sub && <div style={{ fontFamily: T.mono, fontSize: 11, color: T.muted, marginTop: 4 }}>{sub}</div>}
    </div>
    {action && <div style={{ display: 'flex', gap: 8 }}>{action}</div>}
  </div>
);

export const Empty = ({ icon, message }) => (
  <Card style={{ textAlign: 'center', padding: 52 }}>
    <div style={{ fontSize: 34, marginBottom: 14, opacity: .35 }}>{icon}</div>
    <div style={{ fontFamily: T.head, color: T.muted, fontSize: 14 }}>{message}</div>
  </Card>
);

export function useToast() {
  const [toasts, setToasts] = useState([]);
  const toast = (msg, type = 'success') => {
    const id = Date.now();
    setToasts(t => [...t, { id, msg, type }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4500);
  };
  const ToastContainer = (
    <div style={{ position: 'fixed', bottom: 24, right: 24, zIndex: 1000, display: 'flex', flexDirection: 'column', gap: 8 }}>
      {toasts.map(t => (
        <div key={t.id} className="slide-in" style={{
          background: t.type === 'error' ? T.redDim : t.type === 'warn' ? T.orangeDim : T.greenDim,
          border: `1px solid ${t.type === 'error' ? T.red : t.type === 'warn' ? T.orange : T.green}55`,
          color: T.text, fontFamily: T.head, fontSize: 13, padding: '10px 16px',
          borderRadius: 8, boxShadow: '0 4px 20px rgba(0,0,0,.45)', maxWidth: 380,
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <span>{t.type === 'error' ? '✕' : t.type === 'warn' ? '⚠' : '✓'}</span>
          {t.msg}
        </div>
      ))}
    </div>
  );
  return { toast, ToastContainer };
}

export function useConfirm() {
  const [state, setState] = useState(null);
  const confirm = (message, onOk) => setState({ message, onOk });
  const Dialog = state ? (
    <Modal onClose={() => setState(null)} width={380} title="Confirm">
      <div style={{ fontFamily: T.head, color: T.subtle, fontSize: 13, marginBottom: 20 }}>{state.message}</div>
      <div style={{ display: 'flex', gap: 8 }}>
        <Btn variant="danger" onClick={() => { state.onOk(); setState(null); }}>Confirm</Btn>
        <Btn variant="ghost" onClick={() => setState(null)}>Cancel</Btn>
      </div>
    </Modal>
  ) : null;
  return { confirm, Dialog };
}

export function useAsync(fn, deps = []) {
  const [state, setState] = useState({ data: null, loading: true, error: null });
  const reload = () => {
    setState(s => ({ ...s, loading: true, error: null }));
    fn().then(data => setState({ data, loading: false, error: null }))
       .catch(e  => setState({ data: null, loading: false, error: e.message }));
  };
  useEffect(reload, deps);
  return { ...state, reload };
}

export const LoadingPage = ({ message = 'Loading…' }) => (
  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', gap: 12 }}>
    <Spinner size={22} /><span style={{ fontFamily: T.head, color: T.muted }}>{message}</span>
  </div>
);

export const KV = ({ label, value, mono, wide }) => (
  <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', marginBottom: 10 }}>
    <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.07em', width: wide ? 110 : 80, flexShrink: 0, paddingTop: 2 }}>{label}</div>
    <div style={{ fontFamily: mono ? T.mono : T.head, fontSize: mono ? 11 : 13, color: T.text, wordBreak: 'break-word' }}>{value ?? '—'}</div>
  </div>
);

export const StatusDot = ({ status, pulse }) => {
  const c = { pending: T.orange, approved: T.green, rejected: T.muted, draft: T.blue, sent: T.green }[status] || T.muted;
  return <span className={pulse ? 'pulse' : ''} style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: c, flexShrink: 0 }} />;
};

export function FilterTabs({ options, active, onChange }) {
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
      {options.map(({ key, label, count }) => (
        <button key={key} onClick={() => onChange(key)} style={{
          background: active === key ? T.red : T.surface,
          color: active === key ? '#fff' : T.muted,
          border: `1px solid ${active === key ? T.red : T.border}`,
          borderRadius: 6, padding: '5px 14px', fontFamily: T.head, fontSize: 12, fontWeight: 500, cursor: 'pointer',
        }}>
          {label}{count !== undefined ? ` (${count})` : ''}
        </button>
      ))}
    </div>
  );
}

export const KevBadge = () => (
  <span className="kev-pulse" style={{
    background: T.red, color: '#fff', fontFamily: T.mono, fontSize: 10, fontWeight: 700,
    padding: '2px 8px', borderRadius: 4, letterSpacing: '.06em', whiteSpace: 'nowrap',
    display: 'inline-flex', alignItems: 'center', gap: 4,
  }}>🔴 CISA KEV</span>
);

export const CvssTag = ({ score }) => score ? (
  <span style={{
    background: '#1e293b', border: `1px solid ${T.border}`, borderRadius: 4,
    padding: '2px 7px', fontFamily: T.mono, fontSize: 10, color: T.subtle,
    display: 'inline-block', whiteSpace: 'nowrap',
  }}>CVSS {score}</span>
) : null;

export const EpssTag = ({ score }) => score ? (
  <span style={{
    background: '#292215', border: `1px solid ${T.yellow}44`, borderRadius: 4,
    padding: '2px 7px', fontFamily: T.mono, fontSize: 10, color: T.yellow,
    display: 'inline-block', whiteSpace: 'nowrap',
  }}>EPSS {(score * 100).toFixed(1)}%</span>
) : null;

export const AssetTag = ({ name, hasCpe }) => (
  <span style={{
    background: '#0d1520', border: `1px solid ${T.border}`, borderRadius: 4,
    padding: '2px 8px', fontFamily: T.mono, fontSize: 10, color: T.subtle,
    display: 'inline-flex', alignItems: 'center', gap: 5, whiteSpace: 'nowrap',
  }}>
    {name}
    {hasCpe && <span style={{ background: T.tealDim, color: T.teal, borderRadius: 3, padding: '0 4px', fontSize: 9, fontWeight: 700 }}>CPE</span>}
  </span>
);

export const ScoreDot = ({ score }) => {
  const pct = Math.round(Math.min(1, Number(score || 0)) * 100);
  const color = pct >= 90 ? T.green : pct >= 70 ? T.yellow : T.red;
  return <span style={{ display: 'inline-block', width: 7, height: 7, borderRadius: '50%', background: color, flexShrink: 0 }} />;
};

export const SkeletonCard = () => (
  <div style={{ background: T.card, border: `1px solid ${T.border}`, borderRadius: 10, padding: 20, marginBottom: 8 }}>
    <div style={{ display: 'flex', gap: 10, marginBottom: 12 }}>
      <div className="shimmer" style={{ width: 60, height: 18, borderRadius: 4 }} />
      <div className="shimmer" style={{ width: 120, height: 18, borderRadius: 4 }} />
      <div className="shimmer" style={{ width: 80, height: 18, borderRadius: 4 }} />
    </div>
    <div className="shimmer" style={{ width: '70%', height: 16, borderRadius: 4, marginBottom: 10 }} />
    <div className="shimmer" style={{ width: '45%', height: 12, borderRadius: 4, marginBottom: 14 }} />
    <div style={{ display: 'flex', gap: 6 }}>
      <div className="shimmer" style={{ width: 70, height: 22, borderRadius: 4 }} />
      <div className="shimmer" style={{ width: 70, height: 22, borderRadius: 4 }} />
    </div>
  </div>
);
