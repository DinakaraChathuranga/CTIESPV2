// src/api.js
import axios from 'axios';

const http = axios.create({ baseURL: '/api', timeout: 60000 });

// ── Attach JWT token to every request ────────────────────────────────────────
http.interceptors.request.use(config => {
  const token = localStorage.getItem('cti_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// ── Handle 401: clear token and force re-login ────────────────────────────────
http.interceptors.response.use(
  r => r.data,
  e => {
    if (e.response?.status === 401) {
      localStorage.removeItem('cti_token');
      localStorage.removeItem('cti_user');
      window.location.reload();
    }
    const detail = e.response?.data?.detail;
    const msg =
      typeof detail === 'string'   ? detail :
      Array.isArray(detail)        ? detail.map(d => d.msg || JSON.stringify(d)).join(', ') :
      detail != null               ? JSON.stringify(detail) :
      e.response?.data?.error      ||
      e.message                    ||
      'Request failed';
    return Promise.reject(new Error(msg));
  }
);

// ── Auth API ─────────────────────────────────────────────────────────────────
export const authAPI = {
  setupStatus:    ()         => http.get('/auth/setup-status'),
  setup:          (data)     => http.post('/auth/setup', data),
  login:          (data)     => http.post('/auth/login', data),
  me:             ()         => http.get('/auth/me'),
  listUsers:      ()         => http.get('/auth/users'),
  createUser:     (data)     => http.post('/auth/users', data),
  changeRole:     (id, role) => http.patch(`/auth/users/${id}/role?role=${role}`),
  deleteUser:     (id)       => http.delete(`/auth/users/${id}`),
  // Self-service: user provides current password to set a new one (no token required)
  changePassword: (data)     => http.post('/auth/change-password', data),
  // Admin: reset any user's password without needing their current password
  resetPassword:  (id, data) => http.post(`/auth/users/${id}/reset-password`, data),
};

// ── Clients API ───────────────────────────────────────────────────────────────
// FIXED: list() now accepts params so the search query is forwarded to the backend
export const clientsAPI = {
  list:      (params)     => http.get('/clients', { params }),
  get:       (id)         => http.get(`/clients/${id}`),
  create:    (data)       => http.post('/clients', data),
  update:    (id, data)   => http.put(`/clients/${id}`, data),
  delete:    (id)         => http.delete(`/clients/${id}`),
  setAssets: (id, assets) => http.put(`/clients/${id}/assets`, { assets }),
};

// ── CVEs API ──────────────────────────────────────────────────────────────────
export const cvesAPI = {
  list:   (params) => http.get('/cves', { params }),
  count:  (params) => http.get('/cves/count', { params }),
  get:    (id)     => http.get(`/cves/${id}`),
  create: (data)   => http.post('/cves', data),
  delete: (id)     => http.delete(`/cves/${id}`),
  poll:   (source) => http.post(`/cves/poll/${source || 'all'}`),
};

// ── Alerts API ────────────────────────────────────────────────────────────────
export const alertsAPI = {
  list:        (params) => http.get('/alerts', { params }),
  get:         (id)     => http.get(`/alerts/${id}`),
  stats:       ()       => http.get('/alerts/stats'),
  approve:     (id, notes) => http.patch(`/alerts/${id}`, { status: 'approved', notes }),
  reject:      (id, notes) => http.patch(`/alerts/${id}`, { status: 'rejected', notes }),
  restore:     (id, notes) => http.patch(`/alerts/${id}`, { status: 'pending', notes }),
  // Grouped: returns alerts grouped by CVE for batch review
  grouped:     (params) => http.get('/alerts/grouped', { params }),
  // AI verify: calls OpenAI to confirm/deny the match (score >= 80% required)
  // Does NOT auto-approve — analyst still makes the final decision
  verify:      (id)     => http.post(`/alerts/${id}/verify`),
  // Bulk approve: used by grouped view "Approve All Pending" button
  bulkApprove: (data)   => http.post('/alerts/bulk-approve', data),
};

// ── Reports API ───────────────────────────────────────────────────────────────
export const reportsAPI = {
  list:        (params) => http.get('/reports', { params }),
  get:         (id)     => http.get(`/reports/${id}`),
  send:        (id)     => http.post(`/reports/${id}/send`),
  regenerate:  (id)     => http.post(`/reports/${id}/regenerate`),
  downloadUrl: (id)     => `/api/reports/${id}/pdf`,

  // Authenticated file download — triggers browser save dialog
  downloadFile: async (id) => {
    const token = localStorage.getItem('cti_token');
    const res   = await fetch(`/api/reports/${id}/pdf`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!res.ok) {
      const text = await res.text().catch(() => `HTTP ${res.status}`);
      throw new Error(text || `Download failed with status ${res.status}`);
    }

    const blob = await res.blob();

    // Extract filename from Content-Disposition header if present
    let filename = `cti-advisory-${id}.docx`;
    const disposition = res.headers.get('content-disposition');
    const match = disposition && disposition.match(/filename="?([^";\n]+)"?/);
    if (match && match[1]) filename = match[1].trim();

    const url = window.URL.createObjectURL(blob);
    const a   = document.createElement('a');
    a.href     = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  },
};

// ── Sample Reports API ────────────────────────────────────────────────────────
export const samplesAPI = {
  list:   () => http.get('/sample-reports'),
  upload: (file, meta) => {
    const fd = new FormData();
    fd.append('file', file);
    if (meta?.severity)  fd.append('severity', meta.severity);
    if (meta?.vuln_type) fd.append('vuln_type', meta.vuln_type);
    return http.post('/sample-reports/upload', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },
  delete: (docId) => http.delete(`/sample-reports/${docId}`),
};

// ── System API ────────────────────────────────────────────────────────────────
export const systemAPI = {
  health:      () => http.get('/system/health'),
  stats:       () => http.get('/system/stats'),
  embedAssets: () => http.post('/system/embed-assets'),
};

// ── Notifications API ─────────────────────────────────────────────────────────
export const notificationsAPI = {
  list:   ()             => http.get('/notifications/recipients'),
  create: (data)         => http.post('/notifications/recipients', data),
  update: (id, data)     => http.put(`/notifications/recipients/${id}`, data),
  delete: (id)           => http.delete(`/notifications/recipients/${id}`),
  test:   ()             => http.post('/notifications/test'),
};

