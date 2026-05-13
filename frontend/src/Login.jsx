// src/Login.jsx
import { useEffect, useState } from 'react';
import { authAPI } from './api.js';

const S = {
  wrap: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: '#0d0d1a',
    fontFamily: "'Inter', 'Segoe UI', sans-serif",
  },
  card: {
    background: '#13131f',
    border: '1px solid #2a2a3d',
    borderRadius: 12,
    padding: '40px 44px',
    width: 400,
    boxShadow: '0 8px 32px rgba(0,0,0,.5)',
  },
  logo: { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 28 },
  logoIcon: {
    width: 36, height: 36,
    background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
    borderRadius: 8,
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    fontSize: 18,
  },
  logoText: { fontSize: 17, fontWeight: 700, color: '#e0e0f0', letterSpacing: '.01em' },
  logoSub: { fontSize: 11, color: '#6b7280', marginTop: 1 },
  title: { fontSize: 20, fontWeight: 700, color: '#e0e0f0', marginBottom: 6 },
  sub: { fontSize: 13, color: '#6b7280', marginBottom: 28, lineHeight: 1.5 },
  label: { fontSize: 12, color: '#9ca3af', fontWeight: 500, marginBottom: 6, display: 'block' },
  input: {
    width: '100%', boxSizing: 'border-box',
    background: '#1a1a2e', border: '1px solid #2a2a3d',
    borderRadius: 8, padding: '10px 14px',
    fontSize: 14, color: '#e0e0f0', outline: 'none',
    marginBottom: 16, fontFamily: 'inherit',
  },
  btn: {
    width: '100%', padding: '11px 0',
    background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
    border: 'none', borderRadius: 8,
    fontSize: 14, fontWeight: 600, color: '#fff',
    cursor: 'pointer', letterSpacing: '.02em', marginTop: 4,
  },
  secondaryBtn: {
    width: '100%', padding: '10px 0',
    background: '#1a1a2e', border: '1px solid #2a2a3d',
    borderRadius: 8, fontSize: 13, fontWeight: 600,
    color: '#9ca3af', cursor: 'pointer', marginTop: 10,
  },
  err: {
    background: '#2d1515', border: '1px solid #7b2020',
    borderRadius: 8, padding: '10px 14px',
    fontSize: 13, color: '#f87171', marginBottom: 16,
  },
  ok: {
    background: '#102617', border: '1px solid #14532d',
    borderRadius: 8, padding: '10px 14px',
    fontSize: 13, color: '#86efac', marginBottom: 16,
  },
  divider: { borderTop: '1px solid #2a2a3d', margin: '24px 0', position: 'relative' },
  roleBox: {
    background: '#1a1a2e', border: '1px solid #2a2a3d',
    borderRadius: 8, padding: '12px 14px', marginBottom: 12,
  },
  roleTitle: { fontSize: 12, fontWeight: 600, color: '#9ca3af', marginBottom: 4 },
  roleDesc: { fontSize: 12, color: '#6b7280', lineHeight: 1.5 },
};

const INITIAL_FORM = {
  username: '',
  password: '',
  confirm: '',
  currentPassword: '',
  newPassword: '',
  confirmNewPassword: '',
};

export default function Login({ onLogin }) {
  const [mode, setMode] = useState(null); // null=checking, login, setup, change-password
  const [form, setForm] = useState(INITIAL_FORM);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    authAPI.setupStatus()
      .then(r => setMode(r.needs_setup ? 'setup' : 'login'))
      .catch(() => setMode('login'));
  }, []);

  const set = key => e => {
    setError('');
    setSuccess('');
    setForm(f => ({ ...f, [key]: e.target.value }));
  };

  const resetPasswordFields = () => {
    setForm(f => ({
      ...f,
      password: '',
      currentPassword: '',
      newPassword: '',
      confirmNewPassword: '',
    }));
  };

  const goLogin = () => {
    setError('');
    setSuccess('');
    resetPasswordFields();
    setMode('login');
  };

  const handleLogin = async () => {
    if (!form.username || !form.password) return setError('Username and password are required');

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const res = await authAPI.login({ username: form.username.trim(), password: form.password });
      localStorage.setItem('cti_token', res.access_token);
      localStorage.setItem('cti_user', JSON.stringify(res.user));
      onLogin(res.user);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSetup = async () => {
    if (!form.username || !form.password) return setError('Username and password are required');
    if (form.password.length < 8) return setError('Password must be at least 8 characters');
    if (form.password !== form.confirm) return setError('Passwords do not match');

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const res = await authAPI.setup({ username: form.username.trim(), password: form.password });
      localStorage.setItem('cti_token', res.access_token);
      localStorage.setItem('cti_user', JSON.stringify(res.user));
      onLogin(res.user);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async () => {
    if (!form.username || !form.currentPassword || !form.newPassword || !form.confirmNewPassword) {
      return setError('All password change fields are required');
    }
    if (form.newPassword.length < 8) return setError('New password must be at least 8 characters');
    if (form.newPassword !== form.confirmNewPassword) return setError('New passwords do not match');
    if (form.currentPassword === form.newPassword) return setError('New password cannot be the same as the current password');

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const res = await authAPI.changePassword({
        username: form.username.trim(),
        current_password: form.currentPassword,
        new_password: form.newPassword,
        confirm_password: form.confirmNewPassword,
      });
      setSuccess(res.message || 'Password updated successfully. Please sign in with the new password.');
      resetPasswordFields();
      setTimeout(() => setMode('login'), 1200);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const onKey = handler => e => {
    if (e.key === 'Enter') handler();
  };

  if (mode === null) {
    return (
      <div style={S.wrap}>
        <div style={{ color: '#6b7280', fontSize: 14 }}>Loading…</div>
      </div>
    );
  }

  const Header = () => (
    <div style={S.logo}>
      <div style={S.logoIcon}>🛡</div>
      <div>
        <div style={S.logoText}>CTI Platform</div>
        <div style={S.logoSub}>Managed Security Advisory</div>
      </div>
    </div>
  );

  return (
    <div style={S.wrap}>
      <div style={S.card}>
        <Header />

        {mode === 'change-password' ? (
          <>
            <div style={S.title}>Change Password</div>
            <div style={S.sub}>Enter your current username and password, then set a new password.</div>

            {error && <div style={S.err}>{error}</div>}
            {success && <div style={S.ok}>{success}</div>}

            <label style={S.label}>Username</label>
            <input style={S.input} value={form.username} autoFocus onChange={set('username')} onKeyDown={onKey(handleChangePassword)} placeholder="username" />

            <label style={S.label}>Current Password</label>
            <input style={S.input} type="password" value={form.currentPassword} onChange={set('currentPassword')} onKeyDown={onKey(handleChangePassword)} placeholder="••••••••" />

            <label style={S.label}>New Password</label>
            <input style={S.input} type="password" value={form.newPassword} onChange={set('newPassword')} onKeyDown={onKey(handleChangePassword)} placeholder="••••••••" />

            <label style={S.label}>Confirm New Password</label>
            <input style={S.input} type="password" value={form.confirmNewPassword} onChange={set('confirmNewPassword')} onKeyDown={onKey(handleChangePassword)} placeholder="••••••••" />

            <button style={S.btn} onClick={handleChangePassword} disabled={loading}>{loading ? 'Updating password…' : 'Update Password'}</button>
            <button style={S.secondaryBtn} onClick={goLogin} disabled={loading}>Back to Login</button>
          </>
        ) : mode === 'setup' ? (
          <>
            <div style={S.title}>First-time Setup</div>
            <div style={S.sub}>Create your administrator account to get started.</div>

            {error && <div style={S.err}>{error}</div>}

            <label style={S.label}>Username</label>
            <input style={S.input} value={form.username} autoFocus onChange={set('username')} onKeyDown={onKey(handleSetup)} placeholder="admin" />

            <label style={S.label}>Password (min 8 characters)</label>
            <input style={S.input} type="password" value={form.password} onChange={set('password')} onKeyDown={onKey(handleSetup)} placeholder="••••••••" />

            <label style={S.label}>Confirm Password</label>
            <input style={S.input} type="password" value={form.confirm} onChange={set('confirm')} onKeyDown={onKey(handleSetup)} placeholder="••••••••" />

            <button style={S.btn} onClick={handleSetup} disabled={loading}>{loading ? 'Creating account…' : 'Create Admin Account'}</button>

            <div style={S.divider} />
            <div style={S.roleBox}>
              <div style={S.roleTitle}>Security Admin</div>
              <div style={S.roleDesc}>Full access — manage clients, asset registry, sample reports, and users.</div>
            </div>
            <div style={S.roleBox}>
              <div style={S.roleTitle}>Security Reader</div>
              <div style={S.roleDesc}>View alerts and reports. Cannot edit clients or assets.</div>
            </div>
          </>
        ) : (
          <>
            <div style={S.title}>Sign in</div>
            <div style={S.sub}>Enter your credentials to access the CTI platform.</div>

            {error && <div style={S.err}>{error}</div>}
            {success && <div style={S.ok}>{success}</div>}

            <label style={S.label}>Username</label>
            <input style={S.input} value={form.username} autoFocus onChange={set('username')} onKeyDown={onKey(handleLogin)} placeholder="username" />

            <label style={S.label}>Password</label>
            <input style={S.input} type="password" value={form.password} onChange={set('password')} onKeyDown={onKey(handleLogin)} placeholder="••••••••" />

            <button style={S.btn} onClick={handleLogin} disabled={loading}>{loading ? 'Signing in…' : 'Sign In'}</button>
            <button style={S.secondaryBtn} onClick={() => { setError(''); setSuccess(''); resetPasswordFields(); setMode('change-password'); }} disabled={loading}>Change My Password</button>
          </>
        )}
      </div>
    </div>
  );
}
