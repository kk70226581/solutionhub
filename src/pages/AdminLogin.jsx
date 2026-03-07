import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/AdminLogin.css';

const API = import.meta.env.VITE_API_BASE || 'https://solutionhub66.onrender.com';
const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID || '';

const AdminLogin = () => {
  const navigate = useNavigate();
  const googleBtnRef = useRef(null);
  const [loading, setLoading] = useState(false);
  const [configLoading, setConfigLoading] = useState(true);
  const [authConfig, setAuthConfig] = useState(null);
  const [effectiveGoogleClientId, setEffectiveGoogleClientId] = useState(GOOGLE_CLIENT_ID);
  const [step, setStep] = useState('google');
  const [pre2faToken, setPre2faToken] = useState('');
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const isOtpStep = step === 'otp';

  const configItems = [
    {
      ok: !!effectiveGoogleClientId,
      label: 'Frontend client id',
      keyName: 'VITE_GOOGLE_CLIENT_ID',
    },
    {
      ok: !!authConfig?.hasGoogleClientId,
      label: 'Backend Google id',
      keyName: 'GOOGLE_CLIENT_ID',
    },
    {
      ok: !!authConfig?.hasAllowedAdminEmails,
      label: 'Allowed admins',
      keyName: 'ADMIN_ALLOWED_EMAILS',
    },
    {
      ok: !!authConfig?.has2FASecret,
      label: '2FA secret',
      keyName: 'ADMIN_2FA_SECRET / ADMIN_2FA_SECRETS',
    },
  ];

  useEffect(() => {
    let active = true;
    const loadAuthConfig = async () => {
      setConfigLoading(true);
      try {
        const res = await fetch(`${API}/api/admin/auth-config`);
        const data = await res.json().catch(() => ({}));
        if (!active) return;
        if (res.ok && !data?.error) {
          setAuthConfig(data);
          if (!GOOGLE_CLIENT_ID && data?.googleClientId) {
            setEffectiveGoogleClientId(String(data.googleClientId));
          }
        } else setAuthConfig(null);
      } catch {
        if (active) setAuthConfig(null);
      } finally {
        if (active) setConfigLoading(false);
      }
    };
    loadAuthConfig();
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!effectiveGoogleClientId) return;
    let active = true;
    const setupGoogle = () => {
      if (!active || !window.google?.accounts?.id || !googleBtnRef.current) return;
      window.google.accounts.id.initialize({
        client_id: effectiveGoogleClientId,
        callback: async (resp) => {
          if (!resp?.credential) return;
          setLoading(true);
          try {
            const res = await fetch(`${API}/api/admin/google-auth`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ idToken: resp.credential }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok || data?.error) throw new Error(data?.error || 'Google login failed');
            setPre2faToken(data.pre2faToken || '');
            setEmail(data.email || '');
            setStep('otp');
          } catch (err) {
            alert(err.message || 'Google login failed');
          } finally {
            setLoading(false);
          }
        },
      });
      window.google.accounts.id.renderButton(googleBtnRef.current, {
        theme: 'outline',
        size: 'large',
        width: 360,
        text: 'signin_with',
      });
    };

    if (window.google?.accounts?.id) {
      setupGoogle();
      return () => { active = false; };
    }

    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = setupGoogle;
    document.body.appendChild(script);

    return () => { active = false; };
  }, [effectiveGoogleClientId]);

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!code.trim() || loading || !pre2faToken) return;

    setLoading(true);
    try {
      const res = await fetch(`${API}/api/admin/2fa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pre2faToken, code: code.trim() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data?.error) {
        alert(data?.error || 'Invalid admin credentials');
        setLoading(false);
        return;
      }

      localStorage.setItem('adminSessionToken', data.adminSessionToken || '');
      navigate('/admin-dashboard');
    } catch {
      alert('Failed to reach admin API');
      setLoading(false);
    }
  };

  return (
    <div className="admin-login-page">
      <div className="admin-login-bg" aria-hidden />
      <form onSubmit={handleLogin} className="admin-login-card">
        <div className="admin-login-head">
          <div className="admin-login-badge">SolutionHub Security</div>
          <h2>Secure Admin Login</h2>
          <p>
          Step 1: Google sign-in. Step 2: 2FA code from your authenticator app.
          </p>
        </div>

        <div className="admin-login-status-wrap">
          <div className="admin-login-status-title">Auth setup status</div>
          {configLoading ? (
            <div className="admin-login-status-loading">Checking backend config...</div>
          ) : (
            <div className="admin-login-status-list">
              {configItems.map((item) => (
                <div key={item.keyName} className={`admin-login-status-item ${item.ok ? 'ok' : 'bad'}`}>
                  <span className="dot">{item.ok ? '✓' : '!'}</span>
                  <span>{item.label}</span>
                  <code>{item.keyName}</code>
                </div>
              ))}
            </div>
          )}
        </div>

        {!isOtpStep ? (
          <div>
            {!effectiveGoogleClientId ? (
              <div className="admin-login-error">
                Missing Google client id. Set `VITE_GOOGLE_CLIENT_ID` in frontend env or configure backend `GOOGLE_CLIENT_ID`.
              </div>
            ) : null}
            <div ref={googleBtnRef} className="admin-google-wrap" />
          </div>
        ) : (
          <>
            <div className="admin-login-signed-in">
              Signed in as: {email}
            </div>
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="Enter 6-digit 2FA code"
              className="admin-login-input"
              inputMode="numeric"
              autoComplete="one-time-code"
            />
            <button
              type="submit"
              disabled={loading || code.length !== 6}
              className="admin-login-btn primary"
            >
              {loading ? 'Verifying...' : 'Verify 2FA & Open Dashboard'}
            </button>
          </>
        )}

        <button
          type="button"
          onClick={() => navigate('/')}
          className="admin-login-btn ghost"
        >
          Back to Home
        </button>
      </form>
    </div>
  );
};

export default AdminLogin;
