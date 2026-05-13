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
    return Promise.reject(
      new Error(e.response?.data?.detail || e.response?.data?.error || e.message || 'Request failed')
    );
  }
);

// ── Auth API ─────────────────────────────────────────────────────────────────
export const authAPI = {
  setupStatus:  ()           => http.get('/auth/setup-status'),
  setup:        (data)       => http.post('/auth/setup', data),
  login:        (data)       => http.post('/auth/login', data),
  me:           ()           => http.get('/auth/me'),
  listUsers:    ()           => http.get('/auth/users'),
  createUser:   (data)       => http.post('/auth/users', data),
  changeRole:   (id, role)   => http.patch(`/auth/users/${id}/role?role=${role}`),
  deleteUser:   id           => http.delete(`/auth/users/${id}`),
  changePassword: data => http.post('/auth/change-password', data),
  resetPassword:  (id, data) => http.post(`/auth/users/${id}/reset-password`, data),
};

export const clientsAPI = {
  list:      ()               => http.get('/clients'),
  get:       id               => http.get(`/clients/${id}`),
  create:    data             => http.post('/clients', data),
  update:    (id, data)       => http.put(`/clients/${id}`, data),
  delete:    id               => http.delete(`/clients/${id}`),
  setAssets: (id, assets)     => http.put(`/clients/${id}/assets`, { assets }),
};

export const cvesAPI = {
  list:   params => http.get('/cves', { params }),
  count:  params => http.get('/cves/count', { params }),
  get:    id     => http.get(`/cves/${id}`),
  create: data   => http.post('/cves', data),
  delete: id     => http.delete(`/cves/${id}`),
  poll:   source => http.post(`/cves/poll/${source || 'all'}`),
};

export const alertsAPI = {
  list:    params      => http.get('/alerts', { params }),
  get:     id          => http.get(`/alerts/${id}`),
  stats:   ()          => http.get('/alerts/stats'),
  approve: (id, notes) => http.patch(`/alerts/${id}`, { status: 'approved', notes }),
  reject:  (id, notes) => http.patch(`/alerts/${id}`, { status: 'rejected', notes }),
  restore: (id, notes) => http.patch(`/alerts/${id}`, { status: 'pending',  notes }),
  grouped: params => http.get('/alerts/grouped', { params }),
  verify:  id     => http.post(`/alerts/${id}/verify`),
  bulkApprove: data => http.post('/alerts/bulk-approve', data),
};

export const reportsAPI = {
  list:       params => http.get('/reports', { params }),
  get:        id     => http.get(`/reports/${id}`),
  send:       id     => http.post(`/reports/${id}/send`),
  regenerate: id     => http.post(`/reports/${id}/regenerate`),
  downloadUrl: id    => `/api/reports/${id}/pdf`,
downloadFile: async (id) => {
  const token = localStorage.getItem('cti_token');

  const res = await fetch(`/api/reports/${id}/pdf`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Download failed with status ${res.status}`);
  }

  const blob = await res.blob();

  let filename = `cti-report-${id}.docx`;
  const disposition = res.headers.get('content-disposition');
  const match = disposition && disposition.match(/filename="?([^"]+)"?/);
  if (match && match[1]) filename = match[1];

  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
},
};

export const samplesAPI = {
  list:   ()           => http.get('/sample-reports'),
  upload: (file, meta) => {
    const fd = new FormData();
    fd.append('file', file);
    if (meta?.severity)  fd.append('severity', meta.severity);
    if (meta?.vuln_type) fd.append('vuln_type', meta.vuln_type);
    return http.post('/sample-reports/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } });
  },
  delete: docId => http.delete(`/sample-reports/${docId}`),
};

export const systemAPI = {
  health:      () => http.get('/system/health'),
  stats:       () => http.get('/system/stats'),
  embedAssets: () => http.post('/system/embed-assets'),
};
