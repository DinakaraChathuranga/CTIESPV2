// src/api.js
import axios from 'axios';

const http = axios.create({ baseURL: '/api', timeout: 60000 });

http.interceptors.response.use(
  r => r.data,
  e => Promise.reject(new Error(e.response?.data?.detail || e.response?.data?.error || e.message || 'Request failed'))
);

export const clientsAPI = {
  list:      ()          => http.get('/clients'),
  get:       id          => http.get(`/clients/${id}`),
  create:    data        => http.post('/clients', data),
  update:    (id, data)  => http.put(`/clients/${id}`, data),
  delete:    id          => http.delete(`/clients/${id}`),
  setAssets: (id, assets)=> http.put(`/clients/${id}/assets`, { assets }),
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
  list:    params => http.get('/alerts', { params }),
  get:     id     => http.get(`/alerts/${id}`),
  stats:   ()     => http.get('/alerts/stats'),
  approve: (id, notes) => http.patch(`/alerts/${id}`, { status: 'approved', notes, reviewed_by: 'analyst' }),
  reject:  (id, notes) => http.patch(`/alerts/${id}`, { status: 'rejected', notes, reviewed_by: 'analyst' }),
};

export const reportsAPI = {
  list:       params => http.get('/reports', { params }),
  get:        id     => http.get(`/reports/${id}`),
  send:       id     => http.post(`/reports/${id}/send`),
  regenerate: id     => http.post(`/reports/${id}/regenerate`),
  pdfUrl:     id     => `/files/reports/${id}.pdf`,
};

export const samplesAPI = {
  list:   ()             => http.get('/sample-reports'),
  upload: (file, meta)   => {
    const fd = new FormData();
    fd.append('file', file);
    if (meta?.severity)  fd.append('severity', meta.severity);
    if (meta?.vuln_type) fd.append('vuln_type', meta.vuln_type);
    return http.post('/sample-reports/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } });
  },
  delete: docId => http.delete(`/sample-reports/${docId}`),
};

export const systemAPI = {
  health: () => http.get('/system/health'),
  stats:  () => http.get('/system/stats'),
  embedAssets: () => http.post('/system/embed-assets'),
};

// Poll result stream using polling (simple approach)
export async function* pollUntilDone(taskId, intervalMs = 2000, maxRetries = 30) {
  for (let i = 0; i < maxRetries; i++) {
    await new Promise(r => setTimeout(r, intervalMs));
    yield i;
  }
}
