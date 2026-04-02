// src/views.jsx — Dashboard, Clients, Feed, Alerts, Reports, Samples
import { useState, useEffect, useCallback } from 'react';
import { format, formatDistanceToNow } from 'date-fns';
import {
  T, Badge, Btn, Card, Inp, Sel, Textarea, Lbl, Modal, SectionHead,
  Empty, LoadingPage, KV, StatusDot, FilterTabs, PriorityBar,
  useConfirm, useAsync, sevStyle,
} from './ui.jsx';
import { clientsAPI, cvesAPI, alertsAPI, reportsAPI, samplesAPI, systemAPI } from './api.js';

const fmt = d => d ? format(new Date(d), 'dd MMM yyyy HH:mm') : '—';
const ago = d => d ? formatDistanceToNow(new Date(d), { addSuffix: true }) : '—';


// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════

export function Dashboard({ setView }) {
  const { data: stats, reload } = useAsync(() => systemAPI.stats(), []);
  const { data: alerts } = useAsync(() => alertsAPI.list({ limit: 8 }), []);
  const { data: cves }   = useAsync(() => cvesAPI.list({ limit: 6 }), []);
  const { data: health } = useAsync(() => systemAPI.health(), []);
  const [polling, setPoll] = useState(false);

  useEffect(() => { const t = setInterval(reload, 25000); return () => clearInterval(t); }, []);

  const triggerPoll = async () => {
    setPoll(true);
    try { await cvesAPI.poll('all'); setTimeout(reload, 4000); }
    finally { setTimeout(() => setPoll(false), 3000); }
  };

  const s = stats || {};
  const StatCard = ({ label, value, sub, color, icon }) => (
    <Card glow={color + '18'} style={{ flex: 1, borderTop: `3px solid ${color}`, borderColor: color + '33' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.1em', marginBottom: 8 }}>{label}</div>
          <div style={{ fontFamily: T.head, fontSize: 40, fontWeight: 800, color, lineHeight: 1 }}>{value ?? '—'}</div>
          {sub && <div style={{ fontFamily: T.head, fontSize: 12, color: T.muted, marginTop: 6 }}>{sub}</div>}
        </div>
        <span style={{ fontSize: 28, opacity: .2 }}>{icon}</span>
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
              {[['DB', health.db], ['Redis', health.redis], ['Chroma', health.chromadb], ['Model', health.embedding_model_loaded]].map(([k, ok]) => (
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

      {/* Stat cards */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 24 }}>
        <StatCard label="Clients" value={s.clients} icon="◈" color={T.blue} sub="Monitored" />
        <StatCard label="Pending Alerts" value={s.alerts_pending} icon="◎" color={T.orange} sub="Awaiting review" />
        <StatCard label="Critical CVEs" value={s.critical_cves} icon="◉" color={T.red} sub={`${s.kev_cves || 0} in CISA KEV`} />
        <StatCard label="Reports Sent" value={s.reports_sent} icon="▣" color={T.green} sub={`${s.reports_draft || 0} drafts`} />
      </div>

      {/* Poll status */}
      <Card style={{ padding: '12px 18px', marginBottom: 20 }}>
        <div style={{ display: 'flex', gap: 28, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.1em' }}>Last Polls</div>
          {[['NVD', s.last_poll_nvd], ['CISA KEV', s.last_poll_cisa], ['RSS', s.last_poll_rss]].map(([src, t]) => (
            <div key={src} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontFamily: T.head, fontSize: 12, color: T.subtle }}>{src}</span>
              <span style={{ fontFamily: T.mono, fontSize: 11, color: t ? T.green : T.muted }}>
                {t ? ago(t) : 'Never'}
              </span>
            </div>
          ))}
        </div>
      </Card>

      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: 20 }}>
        {/* Recent alerts */}
        <Card>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 15, color: T.text }}>Recent Alerts</div>
            <Btn sm onClick={() => setView('alerts')}>View all →</Btn>
          </div>
          {(alerts || []).length === 0
            ? <div style={{ fontFamily: T.head, color: T.muted, fontSize: 13, textAlign: 'center', padding: '24px 0' }}>No alerts yet</div>
            : (alerts || []).map(a => (
            <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0', borderBottom: `1px solid ${T.border}` }}>
              <StatusDot status={a.status} pulse={a.status === 'pending'} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: T.head, fontSize: 12, color: T.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {a.cve?.cve_ids} — {a.cve?.title?.slice(0, 60)}
                </div>
                <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted }}>
                  {a.client?.name} · {a.match_method} ({Math.round((a.match_score || 0) * 100)}%) · {ago(a.created_at)}
                </div>
              </div>
              <Badge sev={a.cve?.severity} />
            </div>
          ))}
        </Card>

        {/* Latest CVEs */}
        <Card>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 15, color: T.text }}>Latest CVEs</div>
            <Btn sm onClick={() => setView('feed')}>Feed →</Btn>
          </div>
          {(cves || []).map(c => (
            <div key={c.id} style={{ padding: '9px 0', borderBottom: `1px solid ${T.border}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
                <div style={{ fontFamily: T.mono, fontSize: 10, color: T.red }}>{c.cve_ids}</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  {c.is_kev && <span style={{ fontFamily: T.mono, fontSize: 9, color: T.red, background: T.redDim, padding: '1px 5px', borderRadius: 3, border: `1px solid ${T.red}44` }}>KEV</span>}
                  <Badge sev={c.severity} />
                </div>
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

export function Clients({ toast }) {
  const { data: list, reload, loading } = useAsync(() => clientsAPI.list(), []);
  const { confirm, Dialog } = useConfirm();
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({ name: '', email: '', company: '' });
  const [saving, setSaving] = useState(false);
  const [assetInput, setAssetInput] = useState({});
  const [assetCpe, setAssetCpe] = useState({});

  const openNew  = () => { setForm({ name: '', email: '', company: '' }); setModal('new'); };
  const openEdit = c  => { setForm({ name: c.name, email: c.email, company: c.company || '' }); setModal(c.id); };

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

  const addAsset = async (client) => {
    const name = (assetInput[client.id] || '').trim();
    if (!name) return;
    const cpe = (assetCpe[client.id] || '').trim() || null;
    const updated = [...(client.assets || []).map(a => ({ asset_name: a.asset_name, cpe_string: a.cpe_string })),
                     { asset_name: name, cpe_string: cpe }];
    try {
      await clientsAPI.setAssets(client.id, updated);
      setAssetInput(v => ({ ...v, [client.id]: '' }));
      setAssetCpe(v => ({ ...v, [client.id]: '' }));
      toast(`Asset added — embedding in background`);
      reload();
    } catch (e) { toast(e.message, 'error'); }
  };

  const removeAsset = async (client, assetName) => {
    const updated = (client.assets || [])
      .filter(a => a.asset_name !== assetName)
      .map(a => ({ asset_name: a.asset_name, cpe_string: a.cpe_string }));
    try { await clientsAPI.setAssets(client.id, updated); reload(); }
    catch (e) { toast(e.message, 'error'); }
  };

  if (loading) return <LoadingPage message="Loading clients…" />;

  return (
    <div className="slide-in" style={{ padding: 32 }}>
      <SectionHead title="Clients & Asset Registry"
        sub="Asset names are embedded with all-MiniLM-L6-v2 for semantic CVE matching. Add CPE strings for exact matching."
        action={<Btn variant="primary" onClick={openNew}>+ Add Client</Btn>} />

      {(modal === 'new' || (modal && modal !== 'new')) && (
        <Modal title={modal === 'new' ? 'New Client' : 'Edit Client'} onClose={() => setModal(null)}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div><Lbl>Client Name *</Lbl><Inp value={form.name} onChange={e => setForm(f => ({...f, name: e.target.value}))} placeholder="Acme Corporation" /></div>
            <div><Lbl>Security Contact Email *</Lbl><Inp value={form.email} onChange={e => setForm(f => ({...f, email: e.target.value}))} placeholder="security@acme.com" type="email" /></div>
            <div><Lbl>Company / Division</Lbl><Inp value={form.company} onChange={e => setForm(f => ({...f, company: e.target.value}))} placeholder="Optional" /></div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 20 }}>
            <Btn variant="primary" onClick={save} loading={saving}>Save</Btn>
            <Btn variant="ghost" onClick={() => setModal(null)}>Cancel</Btn>
          </div>
        </Modal>
      )}
      {Dialog}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {(list || []).map(c => (
          <Card key={c.id}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
              <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
                <div style={{ width: 44, height: 44, background: T.surface, borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: T.head, fontWeight: 800, fontSize: 20, color: T.red }}>{c.name[0]}</div>
                <div>
                  <div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 15, color: T.text }}>{c.name}</div>
                  <div style={{ fontFamily: T.mono, fontSize: 11, color: T.muted }}>{c.email}</div>
                  {c.company && <div style={{ fontFamily: T.head, fontSize: 12, color: T.subtle }}>{c.company}</div>}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <Btn sm onClick={() => openEdit(c)}>✎ Edit</Btn>
                <Btn sm variant="danger" onClick={() => del(c)}>✕</Btn>
              </div>
            </div>

            <div style={{ borderTop: `1px solid ${T.border}`, paddingTop: 14 }}>
              <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, textTransform: 'uppercase', letterSpacing: '.1em', marginBottom: 10 }}>
                Asset Registry ({(c.assets || []).length} products)
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7, marginBottom: 14 }}>
                {(c.assets || []).map(a => (
                  <span key={a.id} style={{
                    background: T.surface, border: `1px solid ${T.border}`, borderRadius: 6,
                    padding: '4px 10px', fontFamily: T.head, fontSize: 12, color: T.subtle,
                    display: 'inline-flex', alignItems: 'center', gap: 8,
                  }}>
                    {a.has_embedding && <span style={{ color: T.teal, fontSize: 10 }}>⊕</span>}
                    {a.asset_name}
                    {a.cpe_string && <span style={{ fontFamily: T.mono, fontSize: 9, color: T.muted }}>CPE</span>}
                    <button onClick={() => removeAsset(c, a.asset_name)} style={{ background: 'none', border: 'none', color: T.muted, cursor: 'pointer', fontSize: 11 }}>✕</button>
                  </span>
                ))}
                {!(c.assets || []).length && <span style={{ color: T.muted, fontSize: 12 }}>No assets — add products to enable CVE matching</span>}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr auto', gap: 8 }}>
                <Inp value={assetInput[c.id] || ''} onChange={e => setAssetInput(v => ({...v, [c.id]: e.target.value}))}
                  placeholder="Product name (e.g. Cisco FMC, Windows Server 2022)"
                  onKeyDown={e => e.key === 'Enter' && addAsset(c)} />
                <Inp value={assetCpe[c.id] || ''} onChange={e => setAssetCpe(v => ({...v, [c.id]: e.target.value}))}
                  placeholder="CPE string (optional)" style={{ fontFamily: T.mono, fontSize: 11 }} />
                <Btn variant="ghost" onClick={() => addAsset(c)} sm>+ Add</Btn>
              </div>
              <div style={{ fontFamily: T.mono, fontSize: 9, color: T.muted, marginTop: 6 }}>
                ⊕ = embedding ready · CPE = exact match enabled · Press Enter to add quickly
              </div>
            </div>
          </Card>
        ))}
        {!(list || []).length && <Empty icon="◈" message="No clients yet. Add a client to start monitoring." />}
      </div>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════════
// CVE FEED
// ═══════════════════════════════════════════════════════════════════════════════

const INIT_CVE = {
  cve_ids:'', title:'', vuln_type:'', severity:'CRITICAL', cvss_score:'',
  affected_products:'', cpe_strings:'', description:'', impact:'',
  attack_vector:'Remote (Unauthenticated)', remediation:'', refs:'',
};

const PAGE_SIZE = 50;

export function Feed({ toast }) {
  const [sev, setSev] = useState('');
  const [search, setSearch] = useState('');
  const [kev, setKev] = useState(false);
  const [page, setPage] = useState(0);
  const [total, setTotal] = useState(null);

  // Reset to page 0 when filters change
  useEffect(() => setPage(0), [sev, search, kev]);

  const { data: list, reload, loading } = useAsync(() =>
    cvesAPI.list({ severity: sev || undefined, search: search || undefined, is_kev: kev || undefined, limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
    [sev, search, kev, page]);

  // Fetch total count separately for pagination display
  useEffect(() => {
    cvesAPI.count({ severity: sev || undefined, search: search || undefined, is_kev: kev || undefined })
      .then(r => setTotal(r.total))
      .catch(() => setTotal(null));
  }, [sev, search, kev]);
  const [showForm, setForm] = useState(false);
  const [f, setF] = useState(INIT_CVE);
  const [saving, setSaving] = useState(false);
  const [polling, setPoll] = useState('');
  const [expanded, setExp] = useState({});
  const { confirm, Dialog } = useConfirm();

  const poll = async (src) => {
    setPoll(src);
    try { await cvesAPI.poll(src); toast(`Poll triggered for ${src} — check back in ~30s`, 'warn'); setTimeout(reload, 20000); }
    catch (e) { toast(e.message, 'error'); }
    finally { setTimeout(() => setPoll(''), 3000); }
  };

  const submit = async () => {
    if (!f.cve_ids || !f.title) return toast('CVE IDs and Title are required', 'error');
    setSaving(true);
    try {
      const r = await cvesAPI.create({
        cve_ids: f.cve_ids.trim(),
        title: f.title.trim(),
        vuln_type: f.vuln_type,
        severity: f.severity,
        cvss_score: f.cvss_score ? parseFloat(f.cvss_score) : null,
        affected_products: f.affected_products.split(',').map(s => s.trim()).filter(Boolean),
        cpe_strings: f.cpe_strings.split('\n').map(s => s.trim()).filter(Boolean),
        description: f.description,
        impact: f.impact.split('\n').map(s => s.trim()).filter(Boolean),
        attack_vector: f.attack_vector,
        remediation: f.remediation,
        refs: f.refs.split('\n').map(s => s.trim()).filter(Boolean),
      });
      toast(`CVE ingested — ${r.alerts_created} alert(s) for: ${(r.matched_clients || []).join(', ') || 'no matches'}`);
      setF(INIT_CVE); setForm(false); reload();
    } catch (e) { toast(e.message, 'error'); }
    finally { setSaving(false); }
  };

  const del = (cve) => confirm(`Delete ${cve.cve_ids}?`, async () => {
    try { await cvesAPI.delete(cve.id); reload(); toast('CVE deleted'); }
    catch (e) { toast(e.message, 'error'); }
  });

  const inp = (field, ph) => <Inp value={f[field]} onChange={e => setF(p => ({...p, [field]: e.target.value}))} placeholder={ph} />;
  const area = (field, ph, rows) => <Textarea value={f[field]} onChange={e => setF(p => ({...p, [field]: e.target.value}))} placeholder={ph} rows={rows} />;

  return (
    <div className="slide-in" style={{ padding: 32 }}>
      <SectionHead title="CVE Intelligence Feed"
        sub="Auto-ingested from NVD, CISA KEV, and 8 security RSS feeds. All CVEs scored with CVSS + EPSS + KEV priority."
        action={
          <>
            <div style={{ display: 'flex', gap: 6 }}>
              {['nvd','cisa','rss','all'].map(s => (
                <Btn key={s} sm variant="ghost" loading={polling === s} onClick={() => poll(s)}>⟳ {s.toUpperCase()}</Btn>
              ))}
            </div>
            <Btn variant="primary" sm onClick={() => setForm(v => !v)}>+ Manual Ingest</Btn>
          </>
        }
      />

      {showForm && (
        <Card style={{ marginBottom: 22, borderColor: `${T.red}44` }}>
          <div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 15, color: T.text, marginBottom: 18 }}>Manual CVE Entry</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>
            <div><Lbl>CVE ID(s) *</Lbl>{inp('cve_ids', 'CVE-2026-20079, CVE-2026-20131')}</div>
            <div><Lbl>Title *</Lbl>{inp('title', 'Cisco FMC Critical Vulnerabilities')}</div>
            <div><Lbl>Type</Lbl>{inp('vuln_type', 'Authentication Bypass & Remote Code Execution')}</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <div><Lbl>Severity</Lbl>
                <Sel value={f.severity} onChange={e => setF(p => ({...p, severity: e.target.value}))}>
                  {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s}>{s}</option>)}
                </Sel>
              </div>
              <div><Lbl>CVSS</Lbl>{inp('cvss_score', '10.0')}</div>
            </div>
            <div><Lbl>Affected Products (comma-sep)</Lbl>{inp('affected_products', 'Cisco FMC, Cisco SCC')}</div>
            <div><Lbl>CPE Strings (one per line)</Lbl>{area('cpe_strings', 'cpe:2.3:a:cisco:firepower_management_center:*', 2)}</div>
            <div><Lbl>Attack Vector</Lbl>{inp('attack_vector', 'Remote (Unauthenticated)')}</div>
          </div>
          <div style={{ display: 'grid', gap: 14, marginBottom: 18 }}>
            <div><Lbl>Description</Lbl>{area('description', 'Full vulnerability description...', 4)}</div>
            <div><Lbl>Impact (one per line)</Lbl>{area('impact', 'Bypass authentication\nExecute arbitrary code\nGain root access', 3)}</div>
            <div><Lbl>Remediation</Lbl>{area('remediation', 'Apply the latest security patches...', 2)}</div>
            <div><Lbl>References (one URL per line)</Lbl>{area('refs', 'https://...', 3)}</div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <Btn variant="primary" onClick={submit} loading={saving}>Submit & Match Clients</Btn>
            <Btn variant="ghost" onClick={() => { setForm(false); setF(INIT_CVE); }}>Cancel</Btn>
          </div>
        </Card>
      )}

      {/* Filters */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 18, alignItems: 'center', flexWrap: 'wrap' }}>
        <FilterTabs
          options={[
            { key: '', label: 'All' },
            { key: 'CRITICAL', label: 'Critical', count: (list||[]).filter(c => c.severity==='CRITICAL').length },
            { key: 'HIGH',     label: 'High',     count: (list||[]).filter(c => c.severity==='HIGH').length },
            { key: 'MEDIUM',   label: 'Medium' },
          ]}
          active={sev} onChange={setSev}
        />
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: T.head, fontSize: 12, color: T.subtle, cursor: 'pointer' }}>
          <input type="checkbox" checked={kev} onChange={e => setKev(e.target.checked)} />
          CISA KEV only
        </label>
        <Inp value={search} onChange={e => setSearch(e.target.value)} placeholder="Search CVE IDs or title…" style={{ flex: 1, maxWidth: 260 }} />
        <span style={{ fontFamily: T.mono, fontSize: 11, color: T.muted, marginLeft: 'auto' }}>
          {total !== null ? `${total} CVEs total` : `${(list||[]).length} CVEs`}
        </span>
      </div>

      {Dialog}
      {loading ? <LoadingPage message="Loading CVE feed…" /> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {(list || []).map(c => {
            const isExp = expanded[c.id];
            return (
              <Card key={c.id} glow={c.severity==='CRITICAL' ? T.redGlow : c.is_kev ? 'rgba(220,38,38,.07)' : undefined}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 7 }}>
                      <Badge sev={c.severity} />
                      <span style={{ fontFamily: T.mono, fontSize: 10, color: T.red, background: T.redDim, padding: '1px 7px', borderRadius: 4 }}>{c.cve_ids}</span>
                      {c.is_kev && <span style={{ fontFamily: T.mono, fontSize: 9, color: T.red, background: T.redDim, padding: '1px 6px', borderRadius: 3, border: `1px solid ${T.red}55`, fontWeight: 700 }}>🔴 KEV</span>}
                      {c.cvss_score && <span style={{ fontFamily: T.mono, fontSize: 10, color: T.muted }}>CVSS {c.cvss_score}</span>}
                      {c.epss_score && <span style={{ fontFamily: T.mono, fontSize: 10, color: T.yellow }}>EPSS {(c.epss_score*100).toFixed(1)}%</span>}
                      <span style={{ fontFamily: T.mono, fontSize: 9, color: T.muted, background: T.surface, padding: '1px 6px', borderRadius: 3, textTransform: 'uppercase' }}>{c.source}</span>
                    </div>
                    <div style={{ fontFamily: T.head, fontWeight: 600, fontSize: 14, color: T.text, marginBottom: 6 }}>{c.title}</div>
                    <div style={{ marginBottom: 8 }}><PriorityBar score={c.priority_score} /></div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                      {(c.affected_products || []).slice(0, 5).map(p => (
                        <span key={p} style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 4, padding: '2px 8px', fontFamily: T.mono, fontSize: 10, color: T.subtle }}>{p}</span>
                      ))}
                    </div>
                    {isExp && (
                      <div style={{ marginTop: 14, paddingTop: 14, borderTop: `1px solid ${T.border}` }}>
                        {c.description && <div style={{ fontFamily: T.head, fontSize: 12, color: T.subtle, lineHeight: 1.65, marginBottom: 10 }}>{c.description}</div>}
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                          {c.attack_vector && <KV label="Attack Vector" value={c.attack_vector} />}
                          {c.attack_complexity && <KV label="Complexity" value={c.attack_complexity} />}
                          {c.epss_percentile && <KV label="EPSS Percentile" value={`${(c.epss_percentile*100).toFixed(1)}th percentile`} />}
                        </div>
                        {(c.refs || []).length > 0 && (
                          <div style={{ marginTop: 8 }}>
                            {(c.refs || []).map(r => (
                              <a key={r} href={r} target="_blank" rel="noreferrer" style={{ display: 'block', fontFamily: T.mono, fontSize: 10, color: T.blue, wordBreak: 'break-all', marginBottom: 3 }}>{r}</a>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                    <Btn sm onClick={() => setExp(e => ({...e, [c.id]: !e[c.id]}))}>{isExp ? '▲' : '▼'}</Btn>
                    <Btn sm variant="danger" onClick={() => del(c)}>✕</Btn>
                  </div>
                </div>
                <div style={{ fontFamily: T.mono, fontSize: 9, color: T.muted, marginTop: 8 }}>
                  Added {ago(c.date_added)} · Priority {c.priority_score ?? '—'}/100
                </div>
              </Card>
            );
          })}
          {!(list||[]).length && !loading && <Empty icon="◉" message="No CVEs yet. Click 'Poll All Feeds' or add one manually." />}
        </div>
      )}

      {/* Pagination controls */}
      {total !== null && total > PAGE_SIZE && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 16, marginTop: 20, padding: '12px 0' }}>
          <Btn sm variant="ghost" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>← Prev</Btn>
          <span style={{ fontFamily: T.mono, fontSize: 11, color: T.muted }}>
            Page {page + 1} of {Math.ceil(total / PAGE_SIZE)} &nbsp;·&nbsp; {total} total
          </span>
          <Btn sm variant="ghost" onClick={() => setPage(p => p + 1)} disabled={(page + 1) * PAGE_SIZE >= total}>Next →</Btn>
        </div>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════════
// ALERTS
// ═══════════════════════════════════════════════════════════════════════════════

export function Alerts({ toast, onCountChange }) {
  const [status, setStatus] = useState('pending');
  const { data: list, reload, loading } = useAsync(() =>
    alertsAPI.list({ status: status === 'all' ? undefined : status }), [status]);
  const { data: allAlerts } = useAsync(() => alertsAPI.list({}), []);
  const [acting, setActing] = useState({});
  const [detail, setDetail] = useState(null);
  const [noteModal, setNoteModal] = useState(null);
  const [note, setNote] = useState('');

  useEffect(() => {
    if (onCountChange && allAlerts) {
      onCountChange('alerts', allAlerts.filter(a => a.status === 'pending').length);
    }
  }, [allAlerts]);

  const counts = {
    pending:  (allAlerts||[]).filter(a => a.status === 'pending').length,
    approved: (allAlerts||[]).filter(a => a.status === 'approved').length,
    rejected: (allAlerts||[]).filter(a => a.status === 'rejected').length,
  };

  const act = async (id, action, noteText = '') => {
    setActing(a => ({...a, [id]: action}));
    try {
      const r = action === 'approve'
        ? await alertsAPI.approve(id, noteText)
        : await alertsAPI.reject(id, noteText);
      if (action === 'approve') {
        toast(r.report_task_id
          ? `Approved — report generation queued (${r.report_task_id.slice(0,8)}…)`
          : 'Approved');
      } else {
        toast('Alert rejected');
      }
      reload();
    } catch (e) { toast(e.message, 'error'); }
    finally { setActing(a => ({...a, [id]: null})); }
  };

  const openNoteApprove = (id) => { setNoteModal(id); setNote(''); };
  const confirmApprove = () => { act(noteModal, 'approve', note); setNoteModal(null); };

  return (
    <div className="slide-in" style={{ padding: 32 }}>
      <SectionHead title="Alert Queue"
        sub="CVE-to-client matches identified by the two-layer matching engine (CPE exact + semantic similarity). Approve to trigger AI report generation." />

      {/* Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginBottom: 20 }}>
        {[['Pending Review', counts.pending, T.orange], ['Approved', counts.approved, T.green], ['Rejected', counts.rejected, T.muted]].map(([l,v,c]) => (
          <div key={l} style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 8, padding: '14px 18px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ fontFamily: T.head, fontSize: 12, color: T.muted }}>{l}</div>
            <div style={{ fontFamily: T.head, fontSize: 28, fontWeight: 800, color: c }}>{v}</div>
          </div>
        ))}
      </div>

      <div style={{ marginBottom: 20 }}>
        <FilterTabs
          options={[
            { key: 'pending',  label: 'Pending',  count: counts.pending },
            { key: 'approved', label: 'Approved', count: counts.approved },
            { key: 'rejected', label: 'Rejected', count: counts.rejected },
            { key: 'all',      label: 'All' },
          ]}
          active={status} onChange={setStatus}
        />
      </div>

      {/* Detail modal */}
      {detail && (
        <Modal title="Alert Detail" onClose={() => setDetail(null)} width={600}>
          <KV label="CVE ID(s)" value={detail.cve?.cve_ids} mono />
          <KV label="Title"     value={detail.cve?.title} />
          <KV label="Severity"  value={<Badge sev={detail.cve?.severity} />} />
          <KV label="CVSS"      value={detail.cve?.cvss_score} mono />
          <KV label="EPSS"      value={detail.cve?.epss_score ? `${(detail.cve.epss_score*100).toFixed(1)}%` : '—'} />
          <KV label="KEV"       value={detail.cve?.is_kev ? '🔴 Yes — actively exploited' : 'No'} />
          <KV label="Priority"  value={<PriorityBar score={detail.cve?.priority_score} />} wide />
          <KV label="Client"    value={detail.client?.name} />
          <KV label="Email"     value={detail.client?.email} mono />
          <KV label="Matched"   value={(detail.matched_assets || []).join(', ')} />
          <KV label="Method"    value={`${detail.match_method} (${Math.round((detail.match_score||0)*100)}% confidence)`} />
          {detail.matched_cpes?.length > 0 && <KV label="CPEs" value={detail.matched_cpes.join('\n')} mono />}
          {detail.cve?.description && (
            <div style={{ background: T.surface, borderRadius: 8, padding: 14, marginTop: 8 }}>
              <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, marginBottom: 6 }}>DESCRIPTION</div>
              <div style={{ fontFamily: T.head, fontSize: 12, color: T.subtle, lineHeight: 1.65 }}>{detail.cve.description}</div>
            </div>
          )}
          {detail.status === 'pending' && (
            <div style={{ display: 'flex', gap: 8, marginTop: 20 }}>
              <Btn variant="success" loading={acting[detail.id]==='approve'} onClick={() => { openNoteApprove(detail.id); setDetail(null); }}>✓ Approve & Generate Report</Btn>
              <Btn variant="danger"  loading={acting[detail.id]==='reject'}  onClick={() => { act(detail.id,'reject'); setDetail(null); }}>✕ Reject</Btn>
            </div>
          )}
        </Modal>
      )}

      {/* Note modal for approval */}
      {noteModal && (
        <Modal title="Add Analyst Note (optional)" onClose={() => setNoteModal(null)} width={440}>
          <Textarea value={note} onChange={e => setNote(e.target.value)} placeholder="Add any notes for the record…" rows={3} />
          <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
            <Btn variant="success" onClick={confirmApprove}>✓ Approve & Generate Report</Btn>
            <Btn variant="ghost" onClick={() => setNoteModal(null)}>Cancel</Btn>
          </div>
        </Modal>
      )}

      {loading ? <LoadingPage message="Loading alerts…" /> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {(list||[]).map(a => (
            <Card key={a.id} glow={a.status==='pending' ? 'rgba(234,88,12,.07)' : undefined}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 8, flexWrap: 'wrap' }}>
                    <StatusDot status={a.status} pulse={a.status==='pending'} />
                    <span style={{ fontFamily: T.mono, fontSize: 10, color: { pending: T.orange, approved: T.green, rejected: T.muted }[a.status], textTransform: 'uppercase', fontWeight: 600 }}>{a.status}</span>
                    <Badge sev={a.cve?.severity} />
                    <span style={{ fontFamily: T.mono, fontSize: 10, color: T.red, background: T.redDim, padding: '1px 6px', borderRadius: 4 }}>{a.cve?.cve_ids}</span>
                    {a.cve?.is_kev && <span style={{ fontFamily: T.mono, fontSize: 9, color: T.red, fontWeight: 700 }}>🔴 KEV</span>}
                  </div>
                  <div style={{ fontFamily: T.head, fontWeight: 600, fontSize: 14, color: T.text, marginBottom: 6 }}>{a.cve?.title?.slice(0, 100)}</div>
                  <div style={{ marginBottom: 6 }}><PriorityBar score={a.cve?.priority_score} /></div>
                  <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 6, padding: '3px 10px', fontFamily: T.head, fontSize: 12, color: T.text }}>👤 {a.client?.name}</span>
                    <span style={{ fontFamily: T.mono, fontSize: 10, color: T.muted }}>
                      {a.match_method} match · {Math.round((a.match_score||0)*100)}% confidence
                    </span>
                    {(a.matched_assets||[]).length > 0 && (
                      <span style={{ fontFamily: T.mono, fontSize: 10, color: T.teal }}>
                        → {(a.matched_assets||[]).join(', ')}
                      </span>
                    )}
                  </div>
                  <div style={{ fontFamily: T.mono, fontSize: 9, color: T.muted, marginTop: 6 }}>{ago(a.created_at)}</div>
                </div>
                <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                  <Btn sm onClick={() => setDetail(a)}>Details</Btn>
                  {a.status === 'pending' && (
                    <>
                      <Btn sm variant="danger" loading={acting[a.id]==='reject'} disabled={!!acting[a.id]} onClick={() => act(a.id,'reject')}>✕</Btn>
                      <Btn sm variant="success" loading={acting[a.id]==='approve'} disabled={!!acting[a.id]} onClick={() => openNoteApprove(a.id)}>
                        {acting[a.id]==='approve' ? 'Generating…' : '✓ Approve'}
                      </Btn>
                    </>
                  )}
                </div>
              </div>
            </Card>
          ))}
          {!(list||[]).length && <Empty icon="◎" message={`No ${status==='all'?'':status} alerts. CVEs auto-match against client assets.`} />}
        </div>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════════
// REPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export function Reports({ toast }) {
  const [statusFilter, setStatus] = useState('');
  const { data: list, reload, loading } = useAsync(() =>
    reportsAPI.list({ status: statusFilter || undefined }), [statusFilter]);
  const [preview, setPreview] = useState(null);
  const [sending, setSending] = useState({});
  const [regen, setRegen] = useState({});

  const send = async (id) => {
    setSending(s => ({...s, [id]: true}));
    try { await reportsAPI.send(id); toast('Report marked as sent'); reload(); }
    catch (e) { toast(e.message, 'error'); }
    finally { setSending(s => ({...s, [id]: false})); }
  };

  const regenerate = async (id) => {
    setRegen(s => ({...s, [id]: true}));
    try {
      await reportsAPI.regenerate(id);
      toast('Regeneration queued — check back in ~30s', 'warn');
      setTimeout(reload, 15000);
    } catch (e) { toast(e.message, 'error'); }
    finally { setTimeout(() => setRegen(s => ({...s, [id]: false})), 3000); }
  };

  return (
    <div className="slide-in" style={{ padding: 32 }}>
      <SectionHead title="Generated Reports"
        sub="AI-generated security advisories using Claude + RAG (your sample reports as style anchors). Preview, download PDF, or send." />

      <div style={{ marginBottom: 20 }}>
        <FilterTabs
          options={[{ key:'',label:'All' },{ key:'draft',label:'● Draft' },{ key:'sent',label:'✓ Sent' }]}
          active={statusFilter} onChange={setStatus}
        />
      </div>

      {preview && <ReportPreview report={preview} onClose={() => setPreview(null)} />}

      {loading ? <LoadingPage message="Loading reports…" /> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {(list||[]).map(r => {
            const d = r.report_data || {};
            const isDraft = r.status === 'draft';
            return (
              <Card key={r.id} glow={isDraft ? 'rgba(37,99,235,.07)' : undefined}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 8 }}>
                      <Badge sev={r.cve?.severity} />
                      <span style={{
                        fontFamily: T.mono, fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4, textTransform: 'uppercase',
                        color: isDraft ? T.blue : T.green,
                        background: isDraft ? T.blueDim : T.greenDim,
                        border: `1px solid ${isDraft ? T.blue : T.green}44`,
                      }}>{isDraft ? '● Draft' : '✓ Sent'}</span>
                      <span style={{ fontFamily: T.mono, fontSize: 11, color: T.muted }}>{r.alert_number}</span>
                      {(r.rag_examples_used||[]).length > 0 && (
                        <span style={{ fontFamily: T.mono, fontSize: 9, color: T.teal, background: T.tealDim, padding: '1px 6px', borderRadius: 3, border: `1px solid ${T.teal}44` }}>
                          RAG: {(r.rag_examples_used||[]).length} examples
                        </span>
                      )}
                    </div>
                    <div style={{ fontFamily: T.head, fontWeight: 600, fontSize: 14, color: T.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: 6 }}>
                      {d.title || r.cve?.title}
                    </div>
                    <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                      <span style={{ fontFamily: T.head, fontSize: 12, color: T.subtle }}>👤 {r.client?.name}</span>
                      <span style={{ fontFamily: T.mono, fontSize: 10, color: T.muted }}>Generated {ago(r.generated_at)}</span>
                      {r.sent_at && <span style={{ fontFamily: T.mono, fontSize: 10, color: T.green }}>Sent {ago(r.sent_at)}</span>}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                    <Btn sm onClick={() => setPreview(r)}>👁 Preview</Btn>
                    <a href={`/api/reports/${r.id}/pdf`} target="_blank" rel="noreferrer" style={{
                      textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 5,
                      background: 'transparent', color: T.subtle, border: `1px solid ${T.border}`,
                      fontFamily: T.head, fontWeight: 500, fontSize: 12, padding: '5px 11px', borderRadius: 6,
                    }}>↓ PDF</a>
                    <Btn sm variant="teal" loading={regen[r.id]} onClick={() => regenerate(r.id)}>⟳ Regen</Btn>
                    {isDraft && <Btn sm variant="blue" loading={sending[r.id]} onClick={() => send(r.id)}>📤 Send</Btn>}
                  </div>
                </div>
              </Card>
            );
          })}
          {!(list||[]).length && <Empty icon="▣" message="No reports yet. Approve alerts to trigger AI generation." />}
        </div>
      )}
    </div>
  );
}


// Report preview modal — renders the advisory data as formatted HTML matching the PDF
function ReportPreview({ report, onClose }) {
  const d = report.report_data || {};
  const client = report.client || {};
  const today = new Date().toLocaleDateString('en-GB', { day:'numeric', month:'long', year:'numeric' });
  const sevColor = { CRITICAL:'#8B1A1A', HIGH:'#c2410c', MEDIUM:'#b45309', LOW:'#15803d' }[(d.severity||'HIGH').toUpperCase()] || '#8B1A1A';
  const descParas = (d.description || '').split(/\n{2,}/).filter(Boolean);

  return (
    <div className="fade-in" onClick={onClose} style={{ position:'fixed', inset:0, background:'rgba(0,0,0,.87)', zIndex:600, display:'flex', alignItems:'flex-start', justifyContent:'center', overflowY:'auto', padding:'32px 16px' }}>
      <div onClick={e => e.stopPropagation()} style={{ background:'#fff', width:'100%', maxWidth:800, borderRadius:6, overflow:'hidden', boxShadow:'0 25px 80px rgba(0,0,0,.8)' }}>
        <button onClick={onClose} style={{ position:'absolute', top:18, right:18, background:'rgba(255,255,255,.2)', border:'none', color:'#fff', cursor:'pointer', borderRadius:4, padding:'4px 12px', fontFamily:'sans-serif', fontSize:13, zIndex:1 }}>✕ Close</button>

        {/* Header */}
        <div style={{ background:sevColor, padding:'28px 36px 22px' }}>
          <div style={{ fontFamily:'monospace', fontSize:10, color:'rgba(255,255,255,.5)', letterSpacing:'.1em', textTransform:'uppercase', marginBottom:10 }}>{today}</div>
          <h1 style={{ fontFamily:'Georgia, serif', fontWeight:700, fontSize:20, color:'#fff', lineHeight:1.35, margin:0 }}>{d.title}</h1>
          <div style={{ width:50, height:3, background:'rgba(255,255,255,.3)', marginTop:14 }} />
        </div>

        {/* Meta */}
        <div style={{ background:'#f8f0f0', padding:'12px 36px', borderBottom:'1px solid #e0c0c0', display:'grid', gridTemplateColumns:'130px 1fr 130px 1fr', gap:'5px 0' }}>
          {[['Alert Number', report.alert_number],['Type', d.type||'N/A'],['Severity', `${d.severity} (CVSS ${d.cvss_score||'N/A'})`],['Platforms', d.target_platforms||'—']].map(([k,v]) => (
            <>
              <span key={k} style={{ fontFamily:'Arial', fontWeight:700, fontSize:10, color:'#666', paddingTop:2 }}>{k}:</span>
              <span key={k+'v'} style={{ fontFamily:'Georgia, serif', fontSize:11, color:'#1a1a1a' }}>{v||'—'}</span>
            </>
          ))}
        </div>

        <div style={{ padding:'22px 36px 36px' }}>
          {/* EPSS + KEV badges */}
          {(d.epss_note || report.cve?.is_kev) && (
            <div style={{ display:'flex', gap:8, marginBottom:16 }}>
              {d.epss_note && <span style={{ background:'#fef3c7', border:'1px solid #f59e0b', color:'#92400e', fontFamily:'Arial', fontSize:10, fontWeight:600, padding:'2px 10px', borderRadius:3 }}>⚡ {d.epss_note}</span>}
              {report.cve?.is_kev && <span style={{ background:'#fee2e2', border:'1px solid #dc2626', color:'#7f1d1d', fontFamily:'Arial', fontSize:10, fontWeight:700, padding:'2px 10px', borderRadius:3 }}>🔴 CISA KEV — Actively Exploited</span>}
            </div>
          )}

          {/* Overview table */}
          <div style={{ fontFamily:'Arial', fontWeight:700, fontSize:10, color:'#333', textTransform:'uppercase', letterSpacing:'.1em', borderBottom:`2px solid ${sevColor}`, paddingBottom:5, marginBottom:10 }}>Overview</div>
          <table style={{ width:'100%', borderCollapse:'collapse', marginBottom:20, fontSize:11 }}>
            <thead><tr style={{ background:'#2d2d2d' }}>
              {['Product','Severity','CVE ID'].map(h => <th key={h} style={{ color:'#fff', fontFamily:'Arial', fontWeight:700, padding:'7px 12px', textAlign:'left', fontSize:10 }}>{h}</th>)}
            </tr></thead>
            <tbody>
              {(d.overview_table||[]).map((row,i) => (
                <tr key={i} style={{ background: i%2===0?'#fef2f2':'#fff', borderBottom:'1px solid #e8c0c0' }}>
                  <td style={{ fontFamily:'Arial', fontWeight:600, padding:'7px 12px', color:'#1a1a1a', fontSize:11 }}>{row.product}</td>
                  <td style={{ fontFamily:'Arial', fontWeight:700, padding:'7px 12px', color:sevColor, fontSize:11 }}>{row.severity}</td>
                  <td style={{ fontFamily:'monospace', fontSize:10, padding:'7px 12px', color:'#555' }}>{row.cve_id}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Description */}
          <div style={{ fontFamily:'Arial', fontWeight:700, fontSize:10, color:'#333', textTransform:'uppercase', letterSpacing:'.1em', borderBottom:`2px solid ${sevColor}`, paddingBottom:5, marginBottom:10 }}>Description</div>
          <div style={{ background:'#fff', border:'1px solid #e0c0c0', padding:'12px 14px', marginBottom:20 }}>
            {descParas.length > 0
              ? descParas.map((p,i) => <p key={i} style={{ fontFamily:'Georgia, serif', fontSize:11.5, lineHeight:1.7, color:'#1a1a1a', marginBottom: i < descParas.length-1 ? 10 : 0 }}>{p}</p>)
              : <p style={{ fontFamily:'Georgia, serif', fontSize:11.5, color:'#1a1a1a', lineHeight:1.7 }}>{d.description}</p>
            }
          </div>

          {/* Details table */}
          <div style={{ fontFamily:'Arial', fontWeight:700, fontSize:10, color:'#333', textTransform:'uppercase', letterSpacing:'.1em', borderBottom:`2px solid ${sevColor}`, paddingBottom:5, marginBottom:10 }}>Vulnerability Details</div>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11, marginBottom:20 }}>
            <tbody>
              {[
                ['Affected Products', (d.affected_products||[]).map(p => `• ${p}`).join('\n')],
                ['Affected Versions', d.affected_versions],
                ['Severity', d.severity_detail],
                ['Impact', (d.impact||[]).map(i => `• ${i}`).join('\n')],
                ['Attack Vector', d.attack_vector],
                ['Remediations', d.remediation],
                d.client_note ? [`Note for ${client.name}`, d.client_note] : null,
                ['References', (d.references||[]).join('\n')],
                ['Disclaimer', '• Information provided on an "as is" basis, without warranty.\n• Products past End of General Support are not evaluated.'],
              ].filter(Boolean).map(([label,val],i) => (
                <tr key={label} style={{ verticalAlign:'top' }}>
                  <td style={{ background:sevColor, color:'#fff', fontFamily:'Arial', fontWeight:700, fontSize:9.5, padding:'9px 12px', width:145, borderBottom:'1px solid rgba(255,255,255,.12)', whiteSpace:'nowrap' }}>{label}</td>
                  <td style={{ background: i%2===0?'#fff':'#fef9f9', fontFamily:'Georgia, serif', fontSize:11, padding:'9px 14px', lineHeight:1.65, borderBottom:'1px solid #e0c0c0', whiteSpace:'pre-line', color:'#1a1a1a',
                    ...(label.startsWith('Note') ? { background:'#eff6ff', color:'#1e40af', fontStyle:'italic' } : {}) }}>
                    {val||'—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* RAG metadata */}
          {(report.rag_examples_used||[]).length > 0 && (
            <div style={{ fontFamily:'monospace', fontSize:9, color:'#999', borderTop:'1px solid #eee', paddingTop:10 }}>
              Generated with RAG examples: {(report.rag_examples_used||[]).join(', ')}
            </div>
          )}
          <div style={{ fontFamily:'monospace', fontSize:9, color:'#bbb', textAlign:'center', marginTop:8 }}>
            {report.alert_number} · {client.name} · {today} · CONFIDENTIAL
          </div>
        </div>
      </div>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════════
// SAMPLE REPORTS (RAG management)
// ═══════════════════════════════════════════════════════════════════════════════

export function SampleReports({ toast }) {
  const { data: list, reload, loading } = useAsync(() => samplesAPI.list(), []);
  const [uploading, setUploading] = useState(false);
  const [meta, setMeta] = useState({ severity: 'CRITICAL', vuln_type: '' });
  const fileRef = useState(null);
  const { confirm, Dialog } = useConfirm();

  const upload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const r = await samplesAPI.upload(file, meta);
      toast(`Indexed "${r.filename}" — ${r.chars_indexed} chars in ${Math.ceil(r.chars_indexed/1500)} chunks`);
      reload();
    } catch (err) { toast(err.message, 'error'); }
    finally { setUploading(false); e.target.value = ''; }
  };

  const del = (doc) => confirm(`Remove "${doc.filename}" from RAG store?`, async () => {
    try { await samplesAPI.delete(doc.doc_id); toast('Removed'); reload(); }
    catch (e) { toast(e.message, 'error'); }
  });

  return (
    <div className="slide-in" style={{ padding: 32 }}>
      <SectionHead title="Sample Reports — RAG Store"
        sub="Upload your handmade advisory reports (PDF or TXT). These are embedded into ChromaDB and used as style anchors when Claude generates new reports. The more examples, the better the style match." />

      <Card style={{ marginBottom: 22, borderColor: `${T.teal}44`, boxShadow: `0 0 20px rgba(13,148,136,.1)` }}>
        <div style={{ fontFamily: T.head, fontWeight: 700, fontSize: 15, color: T.text, marginBottom: 16 }}>Upload Sample Report</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr auto', gap: 12, alignItems: 'flex-end' }}>
          <div>
            <Lbl>Severity</Lbl>
            <Sel value={meta.severity} onChange={e => setMeta(m => ({...m, severity: e.target.value}))}>
              {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s}>{s}</option>)}
            </Sel>
          </div>
          <div>
            <Lbl>Vulnerability Type</Lbl>
            <Inp value={meta.vuln_type} onChange={e => setMeta(m => ({...m, vuln_type: e.target.value}))} placeholder="e.g. Authentication Bypass, RCE, SQL Injection" />
          </div>
          <div>
            <Lbl>File (PDF or TXT)</Lbl>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: T.tealDim, color: T.teal, border: `1px solid ${T.teal}44`, borderRadius: 6, padding: '7px 14px', fontFamily: T.head, fontWeight: 500, fontSize: 13, cursor: 'pointer', opacity: uploading ? .5 : 1 }}>
              {uploading ? <><Spinner size={14} /> Indexing…</> : '📁 Choose File'}
              <input type="file" accept=".pdf,.txt,.md" onChange={upload} style={{ display: 'none' }} disabled={uploading} />
            </label>
          </div>
        </div>
        <div style={{ fontFamily: T.mono, fontSize: 10, color: T.muted, marginTop: 10 }}>
          Reports are chunked by section, embedded with all-MiniLM-L6-v2, and stored in ChromaDB. At report generation time, the 3 most similar chunks are injected into the Claude prompt as style examples.
        </div>
      </Card>

      {Dialog}

      <div style={{ fontFamily: T.head, fontWeight: 600, fontSize: 14, color: T.text, marginBottom: 14 }}>
        Indexed Reports ({(list||[]).length})
      </div>

      {loading ? <LoadingPage message="Loading sample reports…" /> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {(list||[]).map((doc, i) => (
            <Card key={doc.doc_id || i}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontFamily: T.head, fontWeight: 600, fontSize: 14, color: T.text, marginBottom: 4 }}>
                    📄 {doc.filename}
                  </div>
                  <div style={{ display: 'flex', gap: 10 }}>
                    {doc.severity && <Badge sev={doc.severity} />}
                    {doc.vuln_type && <span style={{ fontFamily: T.head, fontSize: 12, color: T.subtle }}>{doc.vuln_type}</span>}
                    <span style={{ fontFamily: T.mono, fontSize: 10, color: T.teal, background: T.tealDim, padding: '1px 7px', borderRadius: 3 }}>Indexed in ChromaDB</span>
                  </div>
                </div>
                <Btn sm variant="danger" onClick={() => del(doc)}>✕ Remove</Btn>
              </div>
            </Card>
          ))}
          {!(list||[]).length && (
            <Empty icon="📄"
              message="No sample reports yet. Upload your handmade advisory reports to enable style-accurate AI generation. Aim for 10–20+ reports for best results." />
          )}
        </div>
      )}
    </div>
  );
}
