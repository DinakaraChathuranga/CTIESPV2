// src/views.jsx
import { useEffect, useMemo, useState } from 'react';
import { format, formatDistanceToNow } from 'date-fns';
import {
  T, Badge, Btn, Card, Inp, Sel, Textarea, Lbl, Modal, SectionHead,
  Empty, LoadingPage, KV, StatusDot, FilterTabs, PriorityBar,
  useConfirm, useAsync, KevBadge, EpssTag, CvssTag, AssetTag, ScoreDot, SkeletonCard,
} from './ui.jsx';
import {
  clientsAPI, cvesAPI, alertsAPI, reportsAPI, samplesAPI, systemAPI, authAPI, notificationsAPI,
} from './api.js';

const fmt = d => d ? format(new Date(d), 'dd MMM yyyy HH:mm') : '—';
const ago = d => d ? formatDistanceToNow(new Date(d), { addSuffix: true }) : '—';
const pct = v => `${Math.round(Math.min(1, Number(v || 0)) * 100)}%`;
const sevOptions = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const INIT_CVE = {
  cve_ids: '', title: '', vuln_type: '', severity: 'CRITICAL', cvss_score: '',
  affected_products: '', cpe_strings: '', description: '', impact: '',
  attack_vector: 'Remote (Unauthenticated)', remediation: '', refs: '',
  direct_client_id: '', direct_asset_name: '',
};

function SmallMuted({ children }) {
  return <span style={{ fontFamily: T.mono, fontSize: 10, color: T.muted }}>{children}</span>;
}

function Tag({ children, color = T.subtle }) {
  return (
    <span style={{
      background: T.surface, border: `1px solid ${T.border}`, borderRadius: 5,
      padding: '2px 7px', fontFamily: T.mono, fontSize: 10, color,
      display: 'inline-flex', gap: 5, alignItems: 'center',
    }}>{children}</span>
  );
}

function AIStatus({ alert, compact }) {
  if (!alert?.ai_verdict) {
    return <Tag><span style={{ color: T.muted }}>AI: not checked</span></Tag>;
  }
  const v = alert.ai_verdict;
  const color = v === 'MATCHED' ? T.green : v === 'NOT_MATCHED' ? T.red : v === 'UNCERTAIN' ? T.orange : T.muted;
  const icon = v === 'MATCHED' ? '✓' : v === 'NOT_MATCHED' ? '✗' : '?';
  const conf = alert.ai_confidence != null ? ` ${pct(alert.ai_confidence)}` : '';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      <Tag color={color}>AI: {v} {icon}{conf}</Tag>
      {!compact && alert.ai_reason && (
        <span style={{ fontFamily: T.head, fontSize: 11, color: T.muted, fontStyle: 'italic' }}>
          {alert.ai_reason.slice(0, 80)}{alert.ai_reason.length > 80 ? '…' : ''}
        </span>
      )}
    </span>
  );
}

function MatchInfo({ alert }) {
  const score = Math.round(Math.min(1, Number(alert.match_score || 0)) * 100);
  const methodColor = alert.match_method === 'cpe' ? T.teal : '#7c3aed';
  const decColor = alert.match_decision === 'confirmed_match' ? T.green
    : alert.match_decision === 'needs_review' ? T.yellow : T.muted;
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 6, alignItems: 'center' }}>
      <Tag color={methodColor}>{alert.match_method || 'match'}</Tag>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
        <ScoreDot score={alert.match_score} />
        <Tag>{score}%</Tag>
      </span>
      {alert.match_decision && <Tag color={decColor}>{alert.match_decision}</Tag>}
      <AIStatus alert={alert} compact />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════

export function Dashboard({ setView }) {
  const { data: stats, reload } = useAsync(() => systemAPI.stats(), []);
  const { data: alerts, reload: reloadAlerts } = useAsync(() => alertsAPI.list({ limit: 8 }), []);
  const { data: cves } = useAsync(() => cvesAPI.list({ limit: 6 }), []);
  const { data: health } = useAsync(() => systemAPI.health(), []);
  const [polling, setPolling] = useState(false);

  useEffect(() => {
    const t = setInterval(() => { reload(); reloadAlerts(); }, 25000);
    return () => clearInterval(t);
  }, []);

  const triggerPoll = async () => {
    setPolling(true);
    try {
      await cvesAPI.poll('all');
      setTimeout(() => { reload(); reloadAlerts(); }, 4000);
    } finally {
      setTimeout(() => setPolling(false), 3000);
    }
  };

  const s = stats || {};

  const pollAgo = (ts) => {
    if (!ts) return { label: 'Never', color: T.red };
    const ms = Date.now() - new Date(ts).getTime();
    const h = ms / 3600000;
    const color = h <= 7 ? T.green : h <= 24 ? T.yellow : T.red;
    return { label: ago(ts), color };
  };
  const nvdPoll  = pollAgo(s.last_poll_nvd);
  const cisaPoll = pollAgo(s.last_poll_cisa);
  const rssPoll  = pollAgo(s.last_poll_rss);

  const StatCard = ({ label, value, sub, trend, color, icon, pct: barPct }) => (
    <Card glow={color + '18'} style={{ flex: 1, borderTop: `3px solid ${color}`, padding: '18px 20px 0', overflow: 'hidden', transition: 'box-shadow .2s' }}
      onMouseEnter={e => e.currentTarget.style.boxShadow = `0 0 28px ${color}28`}
      onMouseLeave={e => e.currentTarget.style.boxShadow = `0 0 22px ${color}18`}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <div>
          <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.1em', marginBottom: 8 }}>{label}</div>
          <div style={{ fontFamily: T.head, fontSize: 36, fontWeight: 800, color, lineHeight: 1 }}>{value ?? '—'}</div>
          {sub && <div style={{ fontFamily: T.head, fontSize: 12, color: T.muted, marginTop: 5 }}>{sub}</div>}
          {trend && <div style={{ fontFamily: T.mono, fontSize: 10, color: T.subtle, marginTop: 4 }}>{trend}</div>}
        </div>
        <span style={{ fontSize: 26, opacity: .15 }}>{icon}</span>
      </div>
      <div style={{ height: 3, background: T.border, margin: '12px -20px 0', borderRadius: 0 }}>
        <div style={{ width: `${Math.min(100, barPct || 0)}%`, height: '100%', background: color, transition: 'width .5s ease' }} />
      </div>
    </Card>
  );

  return (
    <div className="slide-in" style={{ padding: 32 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 28 }}>
        <div>
          <h1 style={{ fontFamily: T.head, fontSize: 26, fontWeight: 800, color: T.text }}>Operations Dashboard</h1>
          <div style={{ fontFamily: T.mono, fontSize: 11, color: T.muted, marginTop: 4 }}>{new Date().toUTCString()}</div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {health && (
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', background: T.surface, border: `1px solid ${T.border}`, borderRadius: 8, padding: '6px 14px' }}>
              {[['DB', health.db], ['Redis', health.redis], ['Model', health.embedding_model_loaded]].map(([k, ok]) => (
                <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: ok ? T.green : T.red }} />
                  <span style={{ fontFamily: T.mono, fontSize: 9, color: T.muted }}>{k}</span>
                </div>
              ))}
            </div>
          )}
          <Btn variant="ghost" onClick={triggerPoll} loading={polling} sm>⟳ Poll All Feeds</Btn>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 16, marginBottom: 16 }}>
        <StatCard label="Clients" value={s.clients} icon="◈" color={T.blue} sub="Monitored" trend="Active asset registrations" barPct={Math.min(100, (s.clients || 0) * 5)} />
        <StatCard label="Pending Alerts" value={s.alerts_pending} icon="◎" color={T.orange} sub="Awaiting review" trend={`${s.alerts_approved || 0} approved this week`} barPct={Math.min(100, (s.alerts_pending || 0) * 2)} />
        <StatCard label="Critical CVEs" value={s.critical_cves} icon="◉" color={T.red} sub={`${s.kev_cves || 0} in CISA KEV`} trend="Actively exploited in the wild" barPct={Math.min(100, (s.critical_cves || 0) * 3)} />
        <StatCard label="Reports Sent" value={s.reports_sent} icon="▣" color={T.green} sub={`${s.reports_draft || 0} drafts pending`} trend="Advisory emails delivered" barPct={Math.min(100, ((s.reports_sent || 0) / Math.max(1, (s.reports_sent || 0) + (s.reports_draft || 0))) * 100)} />
      </div>

      {/* Feed Status row */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 24, alignItems: 'center' }}>
        <span style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.08em' }}>Feed Status:</span>
        {[['NVD', nvdPoll], ['CISA', cisaPoll], ['RSS', rssPoll]].map(([name, p]) => (
          <span key={name} style={{
            display: 'inline-flex', alignItems: 'center', gap: 5,
            background: T.surface, border: `1px solid ${p.color}44`,
            borderRadius: 20, padding: '3px 10px',
            fontFamily: T.mono, fontSize: 10, color: p.color,
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: p.color, display: 'inline-block' }} />
            {name}: {p.label}
          </span>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: 20 }}>
        <Card>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 15, color: T.text }}>Recent Alerts</div>
            <Btn sm onClick={() => setView('alerts')}>View all →</Btn>
          </div>
          {(alerts || []).length === 0 ? <div style={{ fontFamily: T.head, color: T.muted, fontSize: 13, textAlign: 'center', padding: '24px 0' }}>No alerts yet</div> : (alerts || []).map(a => (
            <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0', borderBottom: `1px solid ${T.border}` }}>
              <StatusDot status={a.status} pulse={a.status === 'pending'} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: T.head, fontSize: 12, color: T.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.cve?.cve_ids} — {a.cve?.title?.slice(0, 70)}</div>
                <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted }}>{a.client?.name} · {a.match_method} ({pct(a.match_score)}) · {ago(a.created_at)}</div>
              </div>
              <Badge sev={a.cve?.severity} />
            </div>
          ))}
        </Card>

        <Card>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 15, color: T.text }}>Latest CVEs</div>
            <Btn sm onClick={() => setView('feed')}>Feed →</Btn>
          </div>
          {(cves || []).map(c => (
            <div key={c.id} style={{ padding: '9px 0', borderBottom: `1px solid ${T.border}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
                <div style={{ fontFamily: T.mono, fontSize: 10, color: T.red }}>{c.cve_ids}</div>
                <div style={{ display: 'flex', gap: 6 }}>{c.is_kev && <Tag color={T.red}>KEV</Tag>}<Badge sev={c.severity} /></div>
              </div>
              <div style={{ fontFamily: T.head, fontSize: 12, color: T.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.title}</div>
              <PriorityBar score={c.priority_score} />
            </div>
          ))}
        </Card>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLIENTS
// ═══════════════════════════════════════════════════════════════════════════════

export function Clients({ toast, isAdmin }) {
  const [search, setSearch] = useState('');
  const { data: list, reload, loading } = useAsync(() => clientsAPI.list({ search: search || undefined }), [search]);
  const { confirm, Dialog } = useConfirm();
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({ name: '', email: '', email_cc: '', company: '' });
  const [saving, setSaving] = useState(false);
  const [assetInput, setAssetInput] = useState({});
  const [assetCpe, setAssetCpe] = useState({});

  const openNew = () => { setForm({ name: '', email: '', email_cc: '', company: '' }); setModal('new'); };
  const openEdit = c => { setForm({ name: c.name, email: c.email, email_cc: c.email_cc || '', company: c.company || '' }); setModal(c.id); };

  const save = async () => {
    if (!form.name || !form.email) return toast('Name and email required', 'error');
    setSaving(true);
    try {
      modal === 'new' ? await clientsAPI.create(form) : await clientsAPI.update(modal, form);
      toast(modal === 'new' ? 'Client created' : 'Client updated');
      setModal(null); reload();
    } catch (e) { toast(e.message, 'error'); }
    finally { setSaving(false); }
  };

  const del = c => confirm(`Delete "${c.name}" and all their alerts/reports?`, async () => {
    try { await clientsAPI.delete(c.id); toast('Deleted'); reload(); }
    catch (e) { toast(e.message, 'error'); }
  });

  const addAsset = async client => {
    const name = (assetInput[client.id] || '').trim();
    if (!name) return;
    const cpe = (assetCpe[client.id] || '').trim() || null;
    const updated = [...(client.assets || []).map(a => ({ asset_name: a.asset_name, cpe_string: a.cpe_string })), { asset_name: name, cpe_string: cpe }];
    try {
      await clientsAPI.setAssets(client.id, updated);
      setAssetInput(v => ({ ...v, [client.id]: '' }));
      setAssetCpe(v => ({ ...v, [client.id]: '' }));
      toast('Asset added — embedding in background');
      reload();
    } catch (e) { toast(e.message, 'error'); }
  };

  const removeAsset = async (client, assetName) => {
    const updated = (client.assets || []).filter(a => a.asset_name !== assetName).map(a => ({ asset_name: a.asset_name, cpe_string: a.cpe_string }));
    try { await clientsAPI.setAssets(client.id, updated); reload(); }
    catch (e) { toast(e.message, 'error'); }
  };

  return (
    <div className="slide-in" style={{ padding: 32 }}>
      <SectionHead title="Clients & Asset Registry" sub="Search clients and assets. Only security admins can edit the asset registry." action={isAdmin ? <Btn variant="primary" onClick={openNew}>+ Add Client</Btn> : null} />

      <Card style={{ marginBottom: 18, padding: 14 }}><Inp value={search} onChange={e => setSearch(e.target.value)} placeholder="Search client, company, email, asset, or CPE…" /></Card>

      {isAdmin && (modal === 'new' || (modal && modal !== 'new')) && (
        <Modal title={modal === 'new' ? 'New Client' : 'Edit Client'} onClose={() => setModal(null)}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div><Lbl>Client Name *</Lbl><Inp value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Acme Corporation" /></div>
            <div><Lbl>TO — Security Contact Email *</Lbl><Inp value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} placeholder="email1@acme.com, email2@acme.com" /></div>
            <div><Lbl>CC — Additional Recipients (optional)</Lbl><Inp value={form.email_cc} onChange={e => setForm(f => ({ ...f, email_cc: e.target.value }))} placeholder="cc1@acme.com, cc2@acme.com" /></div>
            <div><Lbl>Company / Division</Lbl><Inp value={form.company} onChange={e => setForm(f => ({ ...f, company: e.target.value }))} placeholder="Optional" /></div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 20 }}><Btn variant="primary" onClick={save} loading={saving}>Save</Btn><Btn variant="ghost" onClick={() => setModal(null)}>Cancel</Btn></div>
        </Modal>
      )}
      {Dialog}

      {loading ? <LoadingPage message="Loading clients…" /> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {(list || []).map(c => (
            <Card key={c.id}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
                  <div style={{ width: 44, height: 44, background: T.surface, borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: T.head, fontWeight: 800, fontSize: 20, color: T.red }}>{c.name?.[0]}</div>
                  <div><div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 15, color: T.text }}>{c.name}</div><div style={{ fontFamily: T.mono, fontSize: 11, color: T.muted }}>TO: {c.email}</div>{c.email_cc && <div style={{ fontFamily: T.mono, fontSize: 11, color: T.subtle }}>CC: {c.email_cc}</div>}{c.company && <div style={{ fontFamily: T.head, fontSize: 12, color: T.subtle }}>{c.company}</div>}</div>
                </div>
                {isAdmin && <div style={{ display: 'flex', gap: 8 }}><Btn sm onClick={() => openEdit(c)}>✎ Edit</Btn><Btn sm variant="danger" onClick={() => del(c)}>✕</Btn></div>}
              </div>

              <div style={{ borderTop: `1px solid ${T.border}`, paddingTop: 14 }}>
                <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.1em', marginBottom: 10 }}>Asset Registry ({(c.assets || []).length} products)</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7, marginBottom: isAdmin ? 14 : 0 }}>
                  {(c.assets || []).map(a => (
                    <span key={a.id} style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 6, padding: '4px 10px', fontFamily: T.head, fontSize: 12, color: T.subtle, display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                      {a.has_embedding && <span style={{ color: T.teal, fontSize: 10 }}>⊕</span>}{a.asset_name}{a.cpe_string && <span style={{ fontFamily: T.mono, fontSize: 9, color: T.muted }}>CPE</span>}{isAdmin && <button onClick={() => removeAsset(c, a.asset_name)} style={{ background: 'none', border: 'none', color: T.muted, cursor: 'pointer', fontSize: 11 }}>✕</button>}
                    </span>
                  ))}
                  {!(c.assets || []).length && <span style={{ color: T.muted, fontSize: 12 }}>No assets — add products to enable CVE matching</span>}
                </div>

                {isAdmin && <>
                  <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr auto', gap: 8 }}>
                    <Inp value={assetInput[c.id] || ''} onChange={e => setAssetInput(v => ({ ...v, [c.id]: e.target.value }))} placeholder="Product name (e.g. FortiGate FortiOS 7.4)" onKeyDown={e => e.key === 'Enter' && addAsset(c)} />
                    <Inp value={assetCpe[c.id] || ''} onChange={e => setAssetCpe(v => ({ ...v, [c.id]: e.target.value }))} placeholder="CPE string (optional)" style={{ fontFamily: T.mono, fontSize: 11 }} />
                    <Btn variant="ghost" onClick={() => addAsset(c)} sm>+ Add</Btn>
                  </div>
                  <div style={{ fontFamily: T.mono, fontSize: 9, color: T.muted, marginTop: 6 }}>Non-admin users can view assets only. They cannot add, edit, or delete assets.</div>
                </>}
              </div>
            </Card>
          ))}
          {!(list || []).length && <Empty icon="◈" message="No clients or assets matched your search." />}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CVE FEED
// ═══════════════════════════════════════════════════════════════════════════════

export function Feed({ toast, isAdmin }) {
  const [sev, setSev] = useState('');
  const [search, setSearch] = useState('');
  const [kev, setKev] = useState(false);
  const [page, setPage] = useState(0);
  const [total, setTotal] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [f, setF] = useState(INIT_CVE);
  const [saving, setSaving] = useState(false);
  const [polling, setPolling] = useState('');
  const [expanded, setExpanded] = useState({});
  const [clients, setClients] = useState([]);
  const { confirm, Dialog } = useConfirm();

  useEffect(() => setPage(0), [sev, search, kev]);
  useEffect(() => { clientsAPI.list().then(setClients).catch(() => setClients([])); }, []);

  const { data: list, reload, loading } = useAsync(() => cvesAPI.list({ severity: sev || undefined, search: search || undefined, is_kev: kev || undefined, limit: 50, offset: page * 50 }), [sev, search, kev, page]);
  useEffect(() => { cvesAPI.count({ severity: sev || undefined, search: search || undefined, is_kev: kev || undefined }).then(r => setTotal(r.total)).catch(() => setTotal(null)); }, [sev, search, kev]);

  const selectedClient = useMemo(() => clients.find(c => c.id === f.direct_client_id), [clients, f.direct_client_id]);

  const poll = async src => { setPolling(src); try { await cvesAPI.poll(src); toast(`Poll triggered for ${src}`, 'warn'); setTimeout(reload, 20000); } catch (e) { toast(e.message, 'error'); } finally { setTimeout(() => setPolling(''), 3000); } };

  const submit = async () => {
    if (!f.cve_ids || !f.title) return toast('CVE ID and title are required', 'error');
    setSaving(true);
    try {
      const r = await cvesAPI.create({
        cve_ids: f.cve_ids.trim(), title: f.title.trim(), vuln_type: f.vuln_type, severity: f.severity,
        cvss_score: f.cvss_score ? parseFloat(f.cvss_score) : null,
        affected_products: f.affected_products.split(',').map(s => s.trim()).filter(Boolean),
        cpe_strings: f.cpe_strings.split('\n').map(s => s.trim()).filter(Boolean),
        description: f.description,
        impact: f.impact.split('\n').map(s => s.trim()).filter(Boolean),
        attack_vector: f.attack_vector, remediation: f.remediation,
        refs: f.refs.split('\n').map(s => s.trim()).filter(Boolean),
        direct_client_id: f.direct_client_id || null,
        direct_asset_name: f.direct_asset_name || null,
      });
      toast(`CVE ingested — ${r.alerts_created} alert(s): ${(r.matched_clients || []).join(', ') || 'no matches'}`);
      setF(INIT_CVE); setShowForm(false); reload();
    } catch (e) { toast(e.message, 'error'); }
    finally { setSaving(false); }
  };

  const del = cve => confirm(`Delete ${cve.cve_ids}?`, async () => { try { await cvesAPI.delete(cve.id); reload(); toast('CVE deleted'); } catch (e) { toast(e.message, 'error'); } });
  const inp = (field, ph) => <Inp value={f[field]} onChange={e => setF(p => ({ ...p, [field]: e.target.value }))} placeholder={ph} />;
  const area = (field, ph, rows) => <Textarea value={f[field]} onChange={e => setF(p => ({ ...p, [field]: e.target.value }))} placeholder={ph} rows={rows} />;

  return (
    <div className="slide-in" style={{ padding: 32 }}>
      <SectionHead title="CVE Intelligence Feed" sub="Auto-ingested CVEs and manual CVE advisory creation." action={<><div style={{ display: 'flex', gap: 6 }}>{['nvd', 'cisa', 'rss', 'all'].map(src => <Btn key={src} sm variant="ghost" loading={polling === src} onClick={() => poll(src)}>⟳ {src.toUpperCase()}</Btn>)}</div>{isAdmin && <Btn variant="primary" sm onClick={() => setShowForm(v => !v)}>+ Manual Ingest</Btn>}</>} />

      {isAdmin && showForm && <Card style={{ marginBottom: 22, borderColor: `${T.red}44` }}>
        <div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 15, color: T.text, marginBottom: 18 }}>Manual CVE Entry</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>
          <div><Lbl>CVE ID *</Lbl>{inp('cve_ids', 'CVE-2026-XXXXX')}</div>
          <div><Lbl>Title *</Lbl>{inp('title', 'Product vulnerability title')}</div>
          <div><Lbl>Type</Lbl>{inp('vuln_type', 'Remote Code Execution')}</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}><div><Lbl>Severity</Lbl><Sel value={f.severity} onChange={e => setF(p => ({ ...p, severity: e.target.value }))}>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s}>{s}</option>)}</Sel></div><div><Lbl>CVSS</Lbl>{inp('cvss_score', '9.8')}</div></div>
          <div><Lbl>Affected Products</Lbl>{inp('affected_products', 'FortiOS, FortiGate')}</div>
          <div><Lbl>CPE Strings</Lbl>{area('cpe_strings', 'cpe:2.3:o:fortinet:fortios:*', 2)}</div>
          <div><Lbl>Attack Vector</Lbl>{inp('attack_vector', 'Remote (Unauthenticated)')}</div>
          <div><Lbl>Direct Client Alert (optional)</Lbl><Sel value={f.direct_client_id} onChange={e => setF(p => ({ ...p, direct_client_id: e.target.value, direct_asset_name: '' }))}><option value="">Run normal matching engine</option>{(clients || []).map(c => <option key={c.id} value={c.id}>{c.name}</option>)}</Sel></div>
          {f.direct_client_id && <div><Lbl>Direct Asset Name</Lbl><Sel value={f.direct_asset_name} onChange={e => setF(p => ({ ...p, direct_asset_name: e.target.value }))}><option value="">No specific asset selected</option>{(selectedClient?.assets || []).map(a => <option key={a.id} value={a.asset_name}>{a.asset_name}</option>)}</Sel></div>}
        </div>
        <div style={{ display: 'grid', gap: 14, marginBottom: 18 }}><div><Lbl>Description</Lbl>{area('description', 'Full vulnerability description...', 4)}</div><div><Lbl>Impact</Lbl>{area('impact', 'Impact point 1\nImpact point 2', 3)}</div><div><Lbl>Remediation</Lbl>{area('remediation', 'Apply vendor patches...', 2)}</div><div><Lbl>References</Lbl>{area('refs', 'https://...', 3)}</div></div>
        <div style={{ display: 'flex', gap: 8 }}><Btn variant="primary" onClick={submit} loading={saving}>{f.direct_client_id ? 'Create Direct Client Alert' : 'Submit & Match Clients'}</Btn><Btn variant="ghost" onClick={() => { setShowForm(false); setF(INIT_CVE); }}>Cancel</Btn></div>
      </Card>}

      <div style={{ display: 'flex', gap: 10, marginBottom: 18, alignItems: 'center', flexWrap: 'wrap' }}>
        <FilterTabs options={[{ key: '', label: 'All' }, { key: 'CRITICAL', label: 'Critical' }, { key: 'HIGH', label: 'High' }, { key: 'MEDIUM', label: 'Medium' }]} active={sev} onChange={setSev} />
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: T.head, fontSize: 12, color: T.subtle, cursor: 'pointer' }}><input type="checkbox" checked={kev} onChange={e => setKev(e.target.checked)} /> CISA KEV only</label>
        <Inp value={search} onChange={e => setSearch(e.target.value)} placeholder="Search CVE, product, or description…" style={{ flex: 1, maxWidth: 320 }} />
        <SmallMuted>{total !== null ? `${total} CVEs total` : `${(list || []).length} CVEs`}</SmallMuted>
      </div>

      {Dialog}
      {loading ? <LoadingPage message="Loading CVE feed…" /> : <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {(list || []).map(c => {
          const isExp = expanded[c.id];
          return <Card key={c.id} glow={c.severity === 'CRITICAL' ? T.redGlow : undefined}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 7 }}><Badge sev={c.severity} /><Tag color={T.red}>{c.cve_ids}</Tag>{c.is_kev && <Tag color={T.red}>KEV</Tag>}{c.cvss_score && <Tag>CVSS {c.cvss_score}</Tag>}{c.epss_score && <Tag color={T.yellow}>EPSS {(c.epss_score * 100).toFixed(1)}%</Tag>}<Tag>{c.source}</Tag></div>
                <div style={{ fontFamily: T.head, fontWeight: 600, fontSize: 14, color: T.text, marginBottom: 6 }}>{c.title}</div>
                <div style={{ marginBottom: 8 }}><PriorityBar score={c.priority_score} /></div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>{(c.affected_products || []).slice(0, 6).map(p => <Tag key={p}>{p}</Tag>)}</div>
                {isExp && <div style={{ marginTop: 14, paddingTop: 14, borderTop: `1px solid ${T.border}` }}>{c.description && <div style={{ fontFamily: T.head, fontSize: 12, color: T.subtle, lineHeight: 1.65, marginBottom: 10 }}>{c.description}</div>}<div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>{c.attack_vector && <KV label="Attack Vector" value={c.attack_vector} />}{c.attack_complexity && <KV label="Complexity" value={c.attack_complexity} />}{c.epss_percentile && <KV label="EPSS Percentile" value={`${(c.epss_percentile * 100).toFixed(1)}th percentile`} />}</div>{(c.refs || []).slice(0, 10).map(r => <a key={r} href={r} target="_blank" rel="noreferrer" style={{ display: 'block', fontFamily: T.mono, fontSize: 10, color: T.blue, wordBreak: 'break-all', marginBottom: 3 }}>{r}</a>)}</div>}
              </div>
              <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}><Btn sm onClick={() => setExpanded(e => ({ ...e, [c.id]: !e[c.id] }))}>{isExp ? '▲' : 'Details'}</Btn>{isAdmin && <Btn sm variant="danger" onClick={() => del(c)}>Delete</Btn>}</div>
            </div>
          </Card>;
        })}
        {!(list || []).length && <Empty icon="◎" message="No CVEs found." />}
      </div>}

      <div style={{ display: 'flex', gap: 8, marginTop: 18, justifyContent: 'flex-end' }}><Btn sm disabled={page === 0} onClick={() => setPage(p => Math.max(0, p - 1))}>Previous</Btn><Tag>Page {page + 1}</Tag><Btn sm disabled={(list || []).length < 50} onClick={() => setPage(p => p + 1)}>Next</Btn></div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ALERTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── CVE Detail Modal ───────────────────────────────────────────────────────────
function CVEDetailModal({ alert, onClose, toast, reload }) {
  const [working, setWorking] = useState(false);
  const cve = alert.cve || {};
  const verify = async () => { setWorking(true); try { const r = await alertsAPI.verify(alert.id); toast(`AI: ${r.verdict} — ${r.reason}`, r.verdict === 'MATCHED' ? 'success' : 'warn'); reload(); } catch (e) { toast(e.message, 'error'); } finally { setWorking(false); } };
  const approve = async () => { setWorking(true); try { await alertsAPI.approve(alert.id); toast('Approved — report queued'); reload(); onClose(); } catch (e) { toast(e.message, 'error'); } finally { setWorking(false); } };
  const reject = async () => { setWorking(true); try { await alertsAPI.reject(alert.id); toast('Rejected'); reload(); onClose(); } catch (e) { toast(e.message, 'error'); } finally { setWorking(false); } };
  const restore = async () => { setWorking(true); try { await alertsAPI.restore(alert.id); toast('Restored'); reload(); onClose(); } catch (e) { toast(e.message, 'error'); } finally { setWorking(false); } };

  return (
    <Modal onClose={onClose} width={900}>
      {cve.is_kev && (
        <div style={{ background: '#450a0a', border: `1px solid ${T.red}`, borderRadius: 8, padding: '10px 16px', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 16 }}>⚠</span>
          <span style={{ fontFamily: T.head, fontWeight: 700, color: T.red, fontSize: 13 }}>Actively Exploited — CISA Known Exploited Vulnerabilities (KEV)</span>
        </div>
      )}
      <div style={{ display: 'flex', gap: 24 }}>
        {/* Left column 40% */}
        <div style={{ width: '38%', flexShrink: 0 }}>
          <div style={{ fontFamily: T.mono, fontSize: 18, fontWeight: 700, color: T.red, marginBottom: 6 }}>{cve.cve_ids || '—'}</div>
          <div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 14, color: T.text, lineHeight: 1.4, marginBottom: 14 }}>{cve.title || 'Untitled'}</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 14 }}>
            {cve.severity && <Badge sev={cve.severity} />}
            {cve.cvss_score && <CvssTag score={cve.cvss_score} />}
            {cve.epss_score && <EpssTag score={cve.epss_score} />}
            {cve.is_kev && <KevBadge />}
          </div>
          {cve.priority_score != null && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, marginBottom: 4, textTransform: 'uppercase' }}>Priority Score</div>
              <PriorityBar score={cve.priority_score} />
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {cve.source && <KV label="Source" value={<Tag>{cve.source}</Tag>} />}
            {cve.published_date && <KV label="Published" value={fmt(cve.published_date)} />}
            {(cve.affected_products || []).length > 0 && (
              <div>
                <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 6 }}>Affected Products</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {(cve.affected_products || []).map(p => <Tag key={p}>{p}</Tag>)}
                </div>
              </div>
            )}
            {(cve.cpe_strings || []).length > 0 && (
              <div>
                <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 6 }}>CPE Strings ({cve.cpe_strings.length})</div>
                <div style={{ background: T.surface, borderRadius: 6, padding: 8, maxHeight: 100, overflowY: 'auto' }}>
                  {cve.cpe_strings.map(c => <div key={c} style={{ fontFamily: T.mono, fontSize: 9, color: T.muted, marginBottom: 3 }}>{c}</div>)}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right column 60% */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {cve.description && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 6 }}>Description</div>
              <div style={{ fontFamily: T.head, fontSize: 13, color: T.subtle, lineHeight: 1.7, maxHeight: 180, overflowY: 'auto', background: T.surface, borderRadius: 8, padding: 12 }}>{cve.description}</div>
            </div>
          )}
          {(cve.impact || []).length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 6 }}>Impact</div>
              <div style={{ background: T.surface, borderRadius: 8, padding: 12 }}>
                {(Array.isArray(cve.impact) ? cve.impact : [cve.impact]).map((i, idx) => (
                  <div key={idx} style={{ fontFamily: T.head, fontSize: 13, color: T.subtle, lineHeight: 1.6, marginBottom: 4 }}>• {i}</div>
                ))}
              </div>
            </div>
          )}
          {cve.remediation && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 6 }}>Remediation</div>
              <div style={{ background: '#0d2010', border: `1px solid ${T.green}44`, borderRadius: 8, padding: 12, fontFamily: T.head, fontSize: 13, color: '#86efac', lineHeight: 1.6 }}>{cve.remediation}</div>
            </div>
          )}
          {(cve.refs || []).length > 0 && (
            <div>
              <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 6 }}>References</div>
              <div style={{ background: T.surface, borderRadius: 8, padding: 10, maxHeight: 120, overflowY: 'auto' }}>
                {cve.refs.map(r => <a key={r} href={r} target="_blank" rel="noreferrer" style={{ display: 'block', fontFamily: T.mono, fontSize: 10, color: T.blue, wordBreak: 'break-all', marginBottom: 4 }}>{r}</a>)}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Match info footer */}
      <div style={{ marginTop: 20, paddingTop: 20, borderTop: `1px solid ${T.border}` }}>
        <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 10 }}>Match Info — {alert.client?.name || 'Unknown Client'}</div>
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 12 }}>
          <KV label="Client" value={<><div style={{ fontFamily: T.head, fontSize: 13, color: T.text, fontWeight: 600 }}>{alert.client?.name || '—'}</div><div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted }}>{alert.client?.email || ''}</div></>} />
          <KV label="Score" value={<><ScoreDot score={alert.match_score} /> {pct(alert.match_score)}</>} />
          <KV label="Method" value={<Tag color={alert.match_method === 'cpe' ? T.teal : '#7c3aed'}>{alert.match_method || '—'}</Tag>} />
        </div>
        {(alert.matched_assets || []).length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 12 }}>
            {alert.matched_assets.map(a => <AssetTag key={a} name={a} />)}
          </div>
        )}
        {alert.ai_verdict && (
          <div style={{ marginBottom: 12 }}>
            <AIStatus alert={alert} />
            {alert.ai_recommended_action && <div style={{ fontFamily: T.head, fontSize: 12, color: T.muted, marginTop: 6 }}>Recommended: {alert.ai_recommended_action}</div>}
          </div>
        )}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {alert.status === 'pending' && (alert.match_score || 0) >= 0.8 && <Btn variant="blue" onClick={verify} loading={working}>AI Verify</Btn>}
          {alert.status === 'pending' && <><Btn variant="success" onClick={approve} loading={working}>Approve</Btn><Btn variant="danger" onClick={reject} loading={working}>Reject</Btn></>}
          {alert.status === 'rejected' && <Btn variant="orange" onClick={restore} loading={working}>Restore</Btn>}
          <Btn variant="ghost" onClick={onClose}>Close</Btn>
        </div>
      </div>
    </Modal>
  );
}

// ── AlertRow (list view) ───────────────────────────────────────────────────────
function AlertRow({ alert, toast, reload }) {
  const [working, setWorking] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const cve = alert.cve || {};

  const verify = async () => { setWorking(true); try { const r = await alertsAPI.verify(alert.id); toast(`AI: ${r.verdict} — ${r.reason}`, r.verdict === 'MATCHED' ? 'success' : 'warn'); reload(); } catch (e) { toast(e.message, 'error'); } finally { setWorking(false); } };
  const approve = async () => { setWorking(true); try { await alertsAPI.approve(alert.id); toast('Alert approved — report queued'); reload(); } catch (e) { toast(e.message, 'error'); } finally { setWorking(false); } };
  const reject = async () => { setWorking(true); try { await alertsAPI.reject(alert.id); toast('Alert rejected'); reload(); } catch (e) { toast(e.message, 'error'); } finally { setWorking(false); } };
  const restore = async () => { setWorking(true); try { await alertsAPI.restore(alert.id); toast('Alert restored'); reload(); } catch (e) { toast(e.message, 'error'); } finally { setWorking(false); } };

  const score = Math.round(Math.min(1, Number(alert.match_score || 0)) * 100);

  return (
    <>
      {showModal && <CVEDetailModal alert={alert} onClose={() => setShowModal(false)} toast={toast} reload={reload} />}
      <Card style={{ transition: 'border-color .15s, background .15s' }}
        onMouseEnter={e => { e.currentTarget.style.borderColor = '#2a3a55'; e.currentTarget.style.background = '#131f35'; }}
        onMouseLeave={e => { e.currentTarget.style.borderColor = T.border; e.currentTarget.style.background = T.card; }}
      >
        {/* TOP ROW */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 8 }}>
          <StatusDot status={alert.status} pulse={alert.status === 'pending'} />
          <Badge sev={cve.severity} />
          <span style={{ fontFamily: T.mono, fontSize: 11, color: T.red, background: '#2d0a0a', border: `1px solid ${T.red}44`, borderRadius: 4, padding: '1px 7px' }}>{cve.cve_ids || '—'}</span>
          {cve.is_kev && <KevBadge />}
          <Tag>{alert.status}</Tag>
          <div style={{ flex: 1 }} />
          <div style={{ display: 'flex', gap: 6 }}>
            <Btn sm onClick={() => setShowModal(true)}>Details</Btn>
            {alert.status === 'pending' && (alert.match_score || 0) >= 0.8 && <Btn sm variant="blue" onClick={verify} loading={working}>AI Verify</Btn>}
            {alert.status === 'pending' && <><Btn sm variant="success" onClick={approve} loading={working}>Approve</Btn><Btn sm variant="danger" onClick={reject} loading={working}>Reject</Btn></>}
            {alert.status === 'rejected' && <Btn sm variant="orange" onClick={restore} loading={working}>Restore</Btn>}
          </div>
        </div>

        {/* TITLE */}
        <div style={{ fontFamily: T.head, fontWeight: 700, color: T.text, fontSize: 14, marginBottom: 6, lineHeight: 1.4 }}>{cve.title || 'Untitled CVE'}</div>

        {/* META ROW */}
        <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, marginBottom: 8, display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ color: T.subtle, fontWeight: 600 }}>{alert.client?.name || 'Unknown client'}</span>
          <span>·</span>
          <span style={{ color: alert.match_method === 'cpe' ? T.teal : '#a78bfa' }}>{alert.match_method || 'match'}</span>
          <ScoreDot score={alert.match_score} />
          <span>{score}%</span>
          <span>·</span>
          <span>{ago(alert.created_at)}</span>
        </div>

        {/* ASSETS */}
        {(alert.matched_assets || []).length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 8 }}>
            {alert.matched_assets.map(a => <AssetTag key={a} name={a} />)}
          </div>
        )}

        {/* CVSS + EPSS + KEV row */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 8, alignItems: 'center' }}>
          {cve.cvss_score && <CvssTag score={cve.cvss_score} />}
          {cve.epss_score && <EpssTag score={cve.epss_score} />}
          {cve.priority_score != null && (
            <span style={{ fontFamily: T.mono, fontSize: 10, color: T.muted }}>Priority {Math.round(cve.priority_score)}</span>
          )}
        </div>

        {/* AI STATUS */}
        <AIStatus alert={alert} />
      </Card>
    </>
  );
}

// ── Grouped view sub-components ────────────────────────────────────────────────
function GroupClientCard({ alert, toast, reload }) {
  const [working, setWorking] = useState(false);
  const score = Math.round(Math.min(1, Number(alert.match_score || 0)) * 100);
  const methodColor = alert.match_method === 'cpe' ? T.teal : '#7c3aed';
  const decColor = alert.match_decision === 'confirmed_match' ? T.green
    : alert.match_decision === 'needs_review' ? T.yellow : T.muted;

  const doVerify = async () => { setWorking(true); try { const r = await alertsAPI.verify(alert.id); toast(`AI: ${r.verdict} — ${r.reason}`, r.verdict === 'MATCHED' ? 'success' : 'warn'); reload(); } catch (e) { toast(e.message, 'error'); } finally { setWorking(false); } };
  const doApprove = async () => { setWorking(true); try { await alertsAPI.approve(alert.id); toast('Approved — report queued'); reload(); } catch (e) { toast(e.message, 'error'); } finally { setWorking(false); } };
  const doReject = async () => { setWorking(true); try { await alertsAPI.reject(alert.id); toast('Rejected'); reload(); } catch (e) { toast(e.message, 'error'); } finally { setWorking(false); } };

  return (
    <div style={{ background: '#0d1520', border: `1px solid ${T.border}`, borderRadius: 8, padding: '12px 14px', transition: 'border-color .15s' }}
      onMouseEnter={e => e.currentTarget.style.borderColor = '#2a3a55'}
      onMouseLeave={e => e.currentTarget.style.borderColor = T.border}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          {/* Client name + email */}
          <div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 14, color: T.text }}>{alert.client_name || alert.client?.name || '—'}</div>
          {alert.client?.email && <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, marginBottom: 8 }}>{alert.client.email}</div>}

          {/* Matched assets */}
          {(alert.matched_assets || []).length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 8 }}>
              {alert.matched_assets.map(a => <AssetTag key={a} name={a} hasCpe={alert.match_method === 'cpe'} />)}
            </div>
          )}

          {/* Match info row */}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center', marginBottom: 6 }}>
            <Tag color={methodColor}>{alert.match_method === 'cpe' ? 'CPE' : 'Semantic'}</Tag>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              <ScoreDot score={alert.match_score} />
              <Tag>{score}%</Tag>
            </span>
            {alert.match_decision && <Tag color={decColor}>{alert.match_decision}</Tag>}
          </div>

          {/* AI verdict row */}
          {alert.ai_verdict && (
            <div style={{ marginTop: 4 }}>
              <AIStatus alert={alert} />
            </div>
          )}
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'flex-start', flexWrap: 'wrap', flexShrink: 0 }}>
          <Tag>{alert.status}</Tag>
          {alert.status === 'pending' && (alert.match_score || 0) >= 0.8 && (
            <Btn sm variant="blue" onClick={doVerify} loading={working}>AI Verify</Btn>
          )}
          {alert.status === 'pending' && (
            <>
              <Btn sm variant="success" onClick={doApprove} loading={working}>Approve</Btn>
              <Btn sm variant="danger" onClick={doReject} loading={working}>Reject</Btn>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function GroupCard({ group, toast, reload, bulkApprove, defaultExpanded }) {
  const [open, setOpen] = useState(defaultExpanded);
  const pendingCount = group.counts?.pending || 0;
  const clientCount = (group.alerts || []).length;

  return (
    <Card glow={group.severity === 'CRITICAL' ? T.redGlow : undefined} style={{ padding: 0, overflow: 'hidden' }}>
      {/* CVE Group Header */}
      <div
        onClick={() => setOpen(v => !v)}
        style={{ display: 'flex', alignItems: 'flex-start', gap: 16, padding: '16px 20px', cursor: 'pointer', transition: 'background .12s' }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,.02)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        {/* LEFT: badges + CVE ID */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, flexShrink: 0, minWidth: 170 }}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <Badge sev={group.severity} />
            {group.is_kev && <KevBadge />}
          </div>
          <span style={{ fontFamily: T.mono, fontSize: 12, color: T.red, background: '#2d0a0a', border: `1px solid ${T.red}44`, borderRadius: 4, padding: '2px 8px', display: 'inline-block' }}>{group.cve_ids}</span>
          {group.cvss_score && <CvssTag score={group.cvss_score} />}
          {group.epss_score && <EpssTag score={group.epss_score} />}
          {group.priority_score != null && (
            <div style={{ paddingTop: 4 }}>
              <PriorityBar score={group.priority_score} />
            </div>
          )}
        </div>

        {/* MIDDLE: title + description */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 14, color: T.text, lineHeight: 1.4, marginBottom: 6,
            display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
            {group.title}
          </div>
          {group.description && (
            <div style={{ fontFamily: T.head, fontSize: 12, color: T.muted, lineHeight: 1.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {group.description?.slice(0, 150)}{(group.description?.length || 0) > 150 ? '…' : ''}
            </div>
          )}
        </div>

        {/* RIGHT: counts + approve + chevron */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'flex-end', flexShrink: 0 }}>
          <div style={{ display: 'flex', gap: 6 }}>
            {pendingCount > 0 && (
              <span style={{ background: T.orangeDim, color: T.orange, border: `1px solid ${T.orange}44`, borderRadius: 12, padding: '2px 10px', fontFamily: T.mono, fontSize: 10, fontWeight: 600 }}>{pendingCount} pending</span>
            )}
            <span style={{ background: T.blueDim, color: T.blue, border: `1px solid ${T.blue}44`, borderRadius: 12, padding: '2px 10px', fontFamily: T.mono, fontSize: 10, fontWeight: 600 }}>{clientCount} customers</span>
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            {pendingCount > 0 && (
              <Btn sm variant="success" onClick={e => { e.stopPropagation(); bulkApprove(group); }}>Approve All Pending</Btn>
            )}
            <span style={{ color: T.muted, fontSize: 14, transition: 'transform .2s', transform: open ? 'rotate(180deg)' : 'none', display: 'inline-block' }}>⌄</span>
          </div>
        </div>
      </div>

      {/* Expandable client cards */}
      {open && (
        <div className="expand-in" style={{ borderTop: `1px solid ${T.border}`, padding: '12px 20px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {(group.alerts || []).map(a => (
            <GroupClientCard key={a.id} alert={a} toast={toast} reload={reload} />
          ))}
          {!(group.alerts || []).length && (
            <div style={{ fontFamily: T.head, fontSize: 13, color: T.muted, textAlign: 'center', padding: '16px 0' }}>No clients matched this CVE.</div>
          )}
        </div>
      )}
    </Card>
  );
}

// ── Main Alerts component ──────────────────────────────────────────────────────
export function Alerts({ toast, onCountChange }) {
  const [mode, setMode] = useState('grouped');
  const [status, setStatus] = useState('pending');
  const [severity, setSeverity] = useState('');
  const [search, setSearch] = useState('');
  const [minScore, setMinScore] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [allExpanded, setAllExpanded] = useState(false);
  const [expandKey, setExpandKey] = useState(0); // bump to reset all group states

  const params = { status: status || undefined, severity: severity || undefined, search: search || undefined, min_score: minScore ? Number(minScore) / 100 : undefined, kev_only: kevOnly || undefined };
  const { data: list, reload, loading } = useAsync(() => mode === 'grouped' ? alertsAPI.grouped(params) : alertsAPI.list({ ...params, limit: 300 }), [mode, status, severity, search, minScore, kevOnly]);

  useEffect(() => { alertsAPI.stats().then(s => onCountChange?.('alerts', s.pending || 0)).catch(() => {}); }, [list]);

  const bulkApprove = async group => {
    const ids = (group.alerts || []).filter(a => a.status === 'pending').map(a => a.id);
    if (!ids.length) return toast('No pending alerts in this group', 'warn');
    try { const r = await alertsAPI.bulkApprove({ alert_ids: ids, notes: 'Bulk approved from grouped CVE view.' }); toast(`${r.approved} alerts approved — reports queued`); reload(); }
    catch (e) { toast(e.message, 'error'); }
  };

  // Count active filters
  const activeFilters = [status, severity, search, minScore ? `${minScore}%` : '', kevOnly ? 'KEV' : ''].filter(Boolean).length;
  const clearFilters = () => { setStatus('pending'); setSeverity(''); setSearch(''); setMinScore(''); setKevOnly(false); };

  const resultCount = Array.isArray(list) ? list.length : 0;

  const toggleExpandAll = () => {
    setAllExpanded(v => !v);
    setExpandKey(k => k + 1);
  };

  return (
    <div className="slide-in" style={{ padding: 32 }}>
      <SectionHead
        title="Alert Queue"
        sub="Search, verify, approve, reject, and group alerts by CVE."
        action={
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {mode === 'grouped' && (
              <Btn sm variant="ghost" onClick={toggleExpandAll}>
                {allExpanded ? 'Collapse All' : 'Expand All'}
              </Btn>
            )}
            <Btn sm variant={mode === 'grouped' ? 'primary' : 'ghost'} onClick={() => setMode('grouped')}>Grouped</Btn>
            <Btn sm variant={mode === 'list' ? 'primary' : 'ghost'} onClick={() => setMode('list')}>List</Btn>
          </div>
        }
      />

      {/* Filter bar */}
      <Card style={{ marginBottom: 18, padding: 14 }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Search with icon */}
          <div style={{ flex: 1, minWidth: 200, position: 'relative' }}>
            <span style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: T.muted, fontSize: 13, pointerEvents: 'none' }}>⌕</span>
            <Inp value={search} onChange={e => setSearch(e.target.value)} placeholder="Search CVE, client, asset, notes…" style={{ paddingLeft: 30 }} />
          </div>

          <Sel value={status} onChange={e => setStatus(e.target.value)} style={{ width: 150 }}>
            <option value="">All status</option>
            <option value="pending">Pending</option>
            <option value="approved">Approved</option>
            <option value="rejected">Rejected</option>
          </Sel>

          <Sel value={severity} onChange={e => setSeverity(e.target.value)} style={{ width: 150 }}>
            {sevOptions.map(s => <option key={s} value={s}>{s || 'All severity'}</option>)}
          </Sel>

          {/* Min score input with % label */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Inp
              value={minScore}
              onChange={e => setMinScore(e.target.value.replace(/[^\d]/g, ''))}
              placeholder="Min score"
              style={{ width: 90 }}
            />
            {minScore && <span style={{ fontFamily: T.mono, fontSize: 11, color: T.subtle, whiteSpace: 'nowrap' }}>Min {minScore}%</span>}
          </div>

          {/* KEV pill toggle */}
          <button onClick={() => setKevOnly(v => !v)} style={{
            background: kevOnly ? T.red : T.surface,
            color: kevOnly ? '#fff' : T.muted,
            border: `1px solid ${kevOnly ? T.red : T.border}`,
            borderRadius: 20, padding: '6px 14px',
            fontFamily: T.mono, fontSize: 11, fontWeight: 700,
            cursor: 'pointer', transition: 'all .12s',
            display: 'flex', alignItems: 'center', gap: 5, whiteSpace: 'nowrap',
          }}>
            🔴 KEV
          </button>

          {/* Active filters badge */}
          {activeFilters > 0 && (
            <span style={{ background: T.blueDim, color: T.blue, border: `1px solid ${T.blue}44`, borderRadius: 12, padding: '2px 9px', fontFamily: T.mono, fontSize: 10, whiteSpace: 'nowrap' }}>
              {activeFilters} filter{activeFilters > 1 ? 's' : ''} active
            </span>
          )}

          {/* Clear filters */}
          {activeFilters > 0 && (
            <Btn sm variant="ghost" onClick={clearFilters}>✕ Clear</Btn>
          )}

          {/* Result count */}
          <span style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, whiteSpace: 'nowrap', marginLeft: 'auto' }}>
            Showing {resultCount} {mode === 'grouped' ? 'CVE groups' : 'alerts'}
          </span>
        </div>
      </Card>

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <SkeletonCard /><SkeletonCard /><SkeletonCard /><SkeletonCard />
        </div>
      ) : mode === 'grouped' ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {(list || []).map(group => (
            <GroupCard key={`${group.cve_id}-${expandKey}`} group={group} toast={toast} reload={reload} bulkApprove={bulkApprove} defaultExpanded={allExpanded} />
          ))}
          {!(list || []).length && (
            status === 'pending'
              ? <Empty icon="🎉" message="No pending alerts — great job!" />
              : <Empty icon="◎" message="No results match your search." />
          )}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {(list || []).map(a => <AlertRow key={a.id} alert={a} toast={toast} reload={reload} />)}
          {!(list || []).length && (
            status === 'pending'
              ? <Empty icon="🎉" message="No pending alerts — great job!" />
              : <Empty icon="◎" message="No results match your search." />
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export function Reports({ toast }) {
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');
  const [preview, setPreview] = useState(null);

  const { data: list, reload, loading } = useAsync(
    () =>
      reportsAPI.list({
        status: status || undefined,
        search: search || undefined,
      }),
    [status, search]
  );

  const send = async id => {
    try {
      await reportsAPI.send(id);
      toast('Report sent');
      reload();
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const regen = async id => {
    try {
      await reportsAPI.regenerate(id);
      toast('Report regeneration queued', 'warn');
      setTimeout(reload, 5000);
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const download = async id => {
    try {
      await reportsAPI.downloadFile(id);
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  return (
    <div className="slide-in" style={{ padding: 32 }}>
      <SectionHead
        title="Reports"
        sub="Generated CTI advisory documents."
      />

      {preview && (
        <Modal
          title="Report Preview"
          onClose={() => setPreview(null)}
          width={780}
        >
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14 }}>
            <span
              style={{
                background: T.surface,
                border: `1px solid ${T.border}`,
                borderRadius: 5,
                padding: '2px 8px',
                fontFamily: T.mono,
                fontSize: 10,
                color: T.subtle,
              }}
            >
              {preview.alert_number}
            </span>

            <span
              style={{
                background: T.surface,
                border: `1px solid ${T.border}`,
                borderRadius: 5,
                padding: '2px 8px',
                fontFamily: T.mono,
                fontSize: 10,
                color: T.subtle,
                textTransform: 'uppercase',
              }}
            >
              {preview.status}
            </span>

            <span
              style={{
                background: T.surface,
                border: `1px solid ${T.border}`,
                borderRadius: 5,
                padding: '2px 8px',
                fontFamily: T.mono,
                fontSize: 10,
                color: T.subtle,
              }}
            >
              {preview.client?.name || 'Unknown client'}
            </span>

            {preview.cve?.severity && <Badge sev={preview.cve.severity} />}
          </div>

          <div
            style={{
              fontFamily: T.head,
              fontSize: 18,
              fontWeight: 700,
              color: T.text,
              marginBottom: 14,
              lineHeight: 1.35,
            }}
          >
            {preview.report_data?.title || preview.cve?.title || 'Security Advisory'}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <KV label="CVE" value={preview.cve?.cve_ids || '—'} wide />
            <KV label="Client" value={preview.client?.name || '—'} wide />
            <KV label="Generated" value={fmt(preview.generated_at)} wide />
            <KV label="Sent" value={preview.sent_at ? fmt(preview.sent_at) : 'Not sent'} wide />
          </div>

          <div style={{ marginTop: 16 }}>
            <Lbl>Description</Lbl>
            <div
              style={{
                fontFamily: T.head,
                color: T.subtle,
                fontSize: 13,
                lineHeight: 1.7,
                background: T.surface,
                border: `1px solid ${T.border}`,
                borderRadius: 8,
                padding: 12,
                whiteSpace: 'pre-wrap',
              }}
            >
              {preview.report_data?.description ||
                preview.cve?.description ||
                'No description available.'}
            </div>
          </div>

          <div style={{ marginTop: 16 }}>
            <Lbl>Impact</Lbl>
            <div
              style={{
                fontFamily: T.head,
                color: T.subtle,
                fontSize: 13,
                lineHeight: 1.7,
                background: T.surface,
                border: `1px solid ${T.border}`,
                borderRadius: 8,
                padding: 12,
                whiteSpace: 'pre-wrap',
              }}
            >
              {Array.isArray(preview.report_data?.impact)
                ? preview.report_data.impact.map((i, idx) => (
                    <div key={idx}>• {i}</div>
                  ))
                : preview.report_data?.impact ||
                  preview.cve?.impact ||
                  'No impact details available.'}
            </div>
          </div>

          <div style={{ marginTop: 16 }}>
            <Lbl>Remediation</Lbl>
            <div
              style={{
                fontFamily: T.head,
                color: T.subtle,
                fontSize: 13,
                lineHeight: 1.7,
                background: T.surface,
                border: `1px solid ${T.border}`,
                borderRadius: 8,
                padding: 12,
                whiteSpace: 'pre-wrap',
              }}
            >
              {preview.report_data?.remediation ||
                preview.cve?.remediation ||
                'No remediation available.'}
            </div>
          </div>

          {(preview.report_data?.references || preview.cve?.refs || []).length > 0 && (
            <div style={{ marginTop: 16 }}>
              <Lbl>References</Lbl>
              <div
                style={{
                  background: T.surface,
                  border: `1px solid ${T.border}`,
                  borderRadius: 8,
                  padding: 12,
                }}
              >
                {(preview.report_data?.references || preview.cve?.refs || []).map((ref, idx) => (
                  <a
                    key={idx}
                    href={ref}
                    target="_blank"
                    rel="noreferrer"
                    style={{
                      display: 'block',
                      fontFamily: T.mono,
                      fontSize: 10,
                      color: T.blue,
                      wordBreak: 'break-all',
                      marginBottom: 5,
                    }}
                  >
                    {ref}
                  </a>
                ))}
              </div>
            </div>
          )}

          <div style={{ display: 'flex', gap: 8, marginTop: 22 }}>
            <Btn
              variant="blue"
              onClick={() => download(preview.id)}
            >
              Download DOCX
            </Btn>

            <Btn
              variant="ghost"
              onClick={() => regen(preview.id)}
            >
              Regenerate
            </Btn>

            {preview.status !== 'sent' && (
              <Btn
                variant="success"
                onClick={() => send(preview.id)}
              >
                Send
              </Btn>
            )}

            <Btn
              variant="ghost"
              onClick={() => setPreview(null)}
            >
              Close
            </Btn>
          </div>
        </Modal>
      )}

      <Card style={{ marginBottom: 18, padding: 14 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 180px', gap: 10 }}>
          <Inp
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search report, CVE, title, or client…"
          />

          <Sel
            value={status}
            onChange={e => setStatus(e.target.value)}
          >
            <option value="">All status</option>
            <option value="draft">Draft</option>
            <option value="sent">Sent</option>
          </Sel>
        </div>
      </Card>

      {loading ? (
        <LoadingPage message="Loading reports…" />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {(list || []).map(r => (
            <Card key={r.id}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 6 }}>
                    <span
                      style={{
                        background: T.surface,
                        border: `1px solid ${T.border}`,
                        borderRadius: 5,
                        padding: '2px 8px',
                        fontFamily: T.mono,
                        fontSize: 10,
                        color: T.subtle,
                      }}
                    >
                      {r.alert_number}
                    </span>

                    <span
                      style={{
                        background: T.surface,
                        border: `1px solid ${T.border}`,
                        borderRadius: 5,
                        padding: '2px 8px',
                        fontFamily: T.mono,
                        fontSize: 10,
                        color: T.subtle,
                        textTransform: 'uppercase',
                      }}
                    >
                      {r.status}
                    </span>

                    <span
                      style={{
                        background: T.surface,
                        border: `1px solid ${T.border}`,
                        borderRadius: 5,
                        padding: '2px 8px',
                        fontFamily: T.mono,
                        fontSize: 10,
                        color: T.subtle,
                      }}
                    >
                      {r.client?.name || 'Unknown client'}
                    </span>

                    {r.cve?.severity && <Badge sev={r.cve.severity} />}
                  </div>

                  <div
                    style={{
                      fontFamily: T.head,
                      color: T.text,
                      fontWeight: 700,
                      fontSize: 14,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {r.report_data?.title || r.cve?.title || 'Security Advisory'}
                  </div>

                  <div
                    style={{
                      fontFamily: T.mono,
                      fontSize: 10,
                      color: T.muted,
                      marginTop: 5,
                    }}
                  >
                    {r.cve?.cve_ids || 'No CVE'} · Generated {fmt(r.generated_at)}
                    {r.sent_at ? ` · Sent ${fmt(r.sent_at)}` : ''}
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 6, alignItems: 'flex-start', flexWrap: 'wrap' }}>
                  <Btn
                    sm
                    onClick={() => setPreview(r)}
                  >
                    Preview
                  </Btn>

                  <Btn
                    sm
                    variant="blue"
                    onClick={() => download(r.id)}
                  >
                    Download DOCX
                  </Btn>

                  <Btn
                    sm
                    onClick={() => regen(r.id)}
                  >
                    Regenerate
                  </Btn>

                  {r.status !== 'sent' && (
                    <Btn
                      sm
                      variant="success"
                      onClick={() => send(r.id)}
                    >
                      Send
                    </Btn>
                  )}
                </div>
              </div>
            </Card>
          ))}

          {!(list || []).length && (
            <Empty icon="▣" message="No reports found." />
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAMPLE REPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export function SampleReports({ toast, isAdmin }) {
  const { data: list, reload, loading } = useAsync(() => samplesAPI.list(), []);
  const [file, setFile] = useState(null);
  const [severity, setSeverity] = useState('HIGH');
  const [vulnType, setVulnType] = useState('');
  const [uploading, setUploading] = useState(false);
  const { confirm, Dialog } = useConfirm();
  const upload = async () => { if (!file) return toast('Select a file first', 'error'); setUploading(true); try { await samplesAPI.upload(file, { severity, vuln_type: vulnType }); toast('Sample report uploaded'); setFile(null); setVulnType(''); reload(); } catch (e) { toast(e.message, 'error'); } finally { setUploading(false); } };
  const del = item => confirm(`Delete sample report "${item.filename}"?`, async () => { try { await samplesAPI.delete(item.doc_id); toast('Sample report deleted'); reload(); } catch (e) { toast(e.message, 'error'); } });
  return <div className="slide-in" style={{ padding: 32 }}><SectionHead title="Sample Reports" sub="Upload report examples used for advisory style reference." />{isAdmin && <Card style={{ marginBottom: 18 }}><div style={{ display: 'grid', gridTemplateColumns: '1fr 160px 220px auto', gap: 10, alignItems: 'end' }}><div><Lbl>PDF/TXT/Markdown File</Lbl><input type="file" onChange={e => setFile(e.target.files?.[0] || null)} style={{ color: T.subtle, fontFamily: T.head }} /></div><div><Lbl>Severity</Lbl><Sel value={severity} onChange={e => setSeverity(e.target.value)}>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s}>{s}</option>)}</Sel></div><div><Lbl>Vulnerability Type</Lbl><Inp value={vulnType} onChange={e => setVulnType(e.target.value)} placeholder="RCE, Auth Bypass…" /></div><Btn variant="primary" onClick={upload} loading={uploading}>Upload</Btn></div></Card>}{Dialog}{loading ? <LoadingPage message="Loading sample reports…" /> : <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>{(list || []).map(item => <Card key={item.doc_id}><div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}><div><div style={{ fontFamily: T.head, color: T.text, fontWeight: 700 }}>{item.filename}</div><div style={{ display: 'flex', gap: 6, marginTop: 6 }}>{item.severity && <Badge sev={item.severity} />}{item.vuln_type && <Tag>{item.vuln_type}</Tag>}{item.uploaded_at && <Tag>{fmt(item.uploaded_at)}</Tag>}</div></div>{isAdmin && <Btn sm variant="danger" onClick={() => del(item)}>Delete</Btn>}</div></Card>)}{!(list || []).length && <Empty icon="▤" message="No sample reports uploaded." />}</div>}</div>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// USERS
// ═══════════════════════════════════════════════════════════════════════════════

export function Users({ toast, user }) {
  const { data: list, reload, loading } = useAsync(() => authAPI.listUsers(), []);
  const [form, setForm] = useState({ username: '', password: '', role: 'security_reader' });
  const [saving, setSaving] = useState(false);
  const [resetUser, setResetUser] = useState(null);
  const [newPassword, setNewPassword] = useState('');
  const { confirm, Dialog } = useConfirm();
  const create = async () => { if (!form.username || !form.password) return toast('Username and password required', 'error'); setSaving(true); try { await authAPI.createUser(form); toast('User created'); setForm({ username: '', password: '', role: 'security_reader' }); reload(); } catch (e) { toast(e.message, 'error'); } finally { setSaving(false); } };
  const changeRole = async (u, role) => { try { await authAPI.changeRole(u.id, role); toast('Role updated'); reload(); } catch (e) { toast(e.message, 'error'); } };
  const resetPassword = async () => { if (!newPassword || newPassword.length < 8) return toast('New password must be at least 8 characters', 'error'); try { await authAPI.resetPassword(resetUser.id, { new_password: newPassword }); toast(`Password reset for ${resetUser.username}`); setResetUser(null); setNewPassword(''); } catch (e) { toast(e.message, 'error'); } };
  const del = u => confirm(`Delete user "${u.username}"?`, async () => { try { await authAPI.deleteUser(u.id); toast('User deleted'); reload(); } catch (e) { toast(e.message, 'error'); } });
  return <div className="slide-in" style={{ padding: 32 }}><SectionHead title="User Management" sub="Create users, change roles, and reset forgotten passwords." /><Card style={{ marginBottom: 18 }}><div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 180px auto', gap: 10, alignItems: 'end' }}><div><Lbl>Username</Lbl><Inp value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} placeholder="analyst01" /></div><div><Lbl>Password</Lbl><Inp type="password" value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} placeholder="min 8 characters" /></div><div><Lbl>Role</Lbl><Sel value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}><option value="security_reader">security_reader</option><option value="security_admin">security_admin</option></Sel></div><Btn variant="primary" loading={saving} onClick={create}>Create</Btn></div></Card>{Dialog}{resetUser && <Modal title={`Reset password: ${resetUser.username}`} onClose={() => setResetUser(null)} width={420}><Lbl>New Password</Lbl><Inp type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} placeholder="min 8 characters" /><div style={{ display: 'flex', gap: 8, marginTop: 16 }}><Btn variant="primary" onClick={resetPassword}>Reset Password</Btn><Btn variant="ghost" onClick={() => setResetUser(null)}>Cancel</Btn></div></Modal>}{loading ? <LoadingPage message="Loading users…" /> : <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>{(list || []).map(u => <Card key={u.id}><div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}><div><div style={{ fontFamily: T.head, color: T.text, fontWeight: 700 }}>{u.username}</div><div style={{ display: 'flex', gap: 6, marginTop: 6 }}><Tag>{u.role}</Tag><Tag>{u.is_active ? 'active' : 'disabled'}</Tag><Tag>Created {fmt(u.created_at)}</Tag></div></div><div style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}><Sel value={u.role} onChange={e => changeRole(u, e.target.value)} style={{ width: 170 }} disabled={u.id === user?.id}><option value="security_reader">security_reader</option><option value="security_admin">security_admin</option></Sel><Btn sm onClick={() => setResetUser(u)}>Reset Password</Btn><Btn sm variant="danger" disabled={u.id === user?.id} onClick={() => del(u)}>Delete</Btn></div></div></Card>)}</div>}</div>;
}

// ── Notifications: manage system alert recipients ────────────────────────────
export function Notifications({ toast }) {
  const { data: list, reload, loading } = useAsync(() => notificationsAPI.list(), []);
  const [form, setForm] = useState({ email: '', name: '', notify_openai: true, notify_feeds: true, notify_pipeline: true, notify_email_send: true });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const { confirm, Dialog } = useConfirm();

  const add = async () => {
    if (!form.email || !form.email.includes('@')) return toast('Valid email required', 'error');
    setSaving(true);
    try {
      await notificationsAPI.create(form);
      toast('Recipient added');
      setForm({ email: '', name: '', notify_openai: true, notify_feeds: true, notify_pipeline: true, notify_email_send: true });
      reload();
    } catch (e) { toast(e.message, 'error'); }
    finally { setSaving(false); }
  };

  const toggle = async (r, field) => {
    try {
      await notificationsAPI.update(r.id, { [field]: !r[field] });
      reload();
    } catch (e) { toast(e.message, 'error'); }
  };

  const del = r => confirm(`Remove ${r.email} from system alerts?`, async () => {
    try { await notificationsAPI.delete(r.id); toast('Recipient removed'); reload(); }
    catch (e) { toast(e.message, 'error'); }
  });

  const sendTest = async () => {
    setTesting(true);
    try {
      const r = await notificationsAPI.test();
      toast(r.sent ? 'Test emails dispatched' : 'No alerts sent — check throttle or recipients', r.sent ? 'success' : 'warn');
    } catch (e) { toast(e.message, 'error'); }
    finally { setTesting(false); }
  };

  const CategoryToggle = ({ rec, field, label }) => (
    <button
      onClick={() => toggle(rec, field)}
      style={{
        padding: '4px 10px', borderRadius: 6, border: 'none', cursor: 'pointer',
        fontSize: 11, fontFamily: T.head, fontWeight: 600,
        background: rec[field] ? T.green + '22' : T.muted + '22',
        color: rec[field] ? T.green : T.muted,
        transition: 'all 0.15s',
      }}
      title={`${rec[field] ? 'Subscribed to' : 'Not subscribed to'} ${label} alerts`}
    >
      {label} {rec[field] ? '✓' : '✗'}
    </button>
  );

  return (
    <div className="slide-in" style={{ padding: 32 }}>
      <SectionHead
        title="System Alert Notifications"
        sub="Recipients listed below will receive emails when OpenAI quota is exhausted, feeds fail, the auto-pipeline errors, or report delivery fails."
        action={<Btn onClick={sendTest} loading={testing}>Send Test Alert</Btn>}
      />

      {Dialog}

      <Card style={{ marginBottom: 18 }}>
        <div style={{ fontFamily: T.head, fontSize: 13, color: T.text, fontWeight: 700, marginBottom: 10 }}>
          Add Recipient
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 10, alignItems: 'end' }}>
          <div>
            <Lbl>Email *</Lbl>
            <Inp value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} placeholder="analyst@example.com" />
          </div>
          <div>
            <Lbl>Name (optional)</Lbl>
            <Inp value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Jane Doe" />
          </div>
          <Btn variant="primary" loading={saving} onClick={add}>+ Add</Btn>
        </div>
        <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, marginTop: 8 }}>
          New recipients receive all 4 categories of alerts by default. Toggle individual categories on the list below.
        </div>
      </Card>

      {loading ? <LoadingPage message="Loading recipients..." /> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {(list || []).map(r => (
            <Card key={r.id}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontFamily: T.head, fontSize: 14, color: T.text, fontWeight: 700 }}>
                    {r.name || r.email}
                  </div>
                  <div style={{ fontFamily: T.mono, fontSize: 11, color: T.muted, marginTop: 2 }}>
                    {r.email}
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
                    <CategoryToggle rec={r} field="notify_openai"     label="OpenAI" />
                    <CategoryToggle rec={r} field="notify_feeds"      label="Feeds" />
                    <CategoryToggle rec={r} field="notify_pipeline"   label="Pipeline" />
                    <CategoryToggle rec={r} field="notify_email_send" label="Email Send" />
                    <button
                      onClick={() => toggle(r, 'enabled')}
                      style={{
                        padding: '4px 10px', borderRadius: 6, border: 'none', cursor: 'pointer',
                        fontSize: 11, fontFamily: T.head, fontWeight: 600,
                        background: r.enabled ? T.blue + '22' : T.red + '22',
                        color: r.enabled ? T.blue : T.red,
                      }}
                    >
                      {r.enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>
                </div>
                <Btn sm variant="danger" onClick={() => del(r)}>Remove</Btn>
              </div>
            </Card>
          ))}
          {!(list || []).length && <Empty icon="!" message="No notification recipients configured yet." />}
        </div>
      )}
    </div>
  );
}

