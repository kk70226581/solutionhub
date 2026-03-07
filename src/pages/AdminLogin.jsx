import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

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
    <div style={{ minHeight: '100vh', background: '#030712', color: '#f0f6ff', display: 'grid', placeItems: 'center', padding: 16 }}>
      <form onSubmit={handleLogin} style={{ width: '100%', maxWidth: 420, background: 'rgba(9,16,36,.92)', border: '1px solid rgba(148,163,184,.22)', borderRadius: 14, padding: 20 }}>
        <h2 style={{ marginBottom: 8 }}>Secure Admin Login</h2>
        <p style={{ marginBottom: 14, color: '#94a3b8', fontSize: 14 }}>
          Step 1: Google sign-in. Step 2: 2FA code from your authenticator app.
        </p>

        <div style={{ marginBottom: 12, border: '1px solid rgba(148,163,184,.22)', borderRadius: 10, padding: 10, background: 'rgba(2,6,23,.5)' }}>
          <div style={{ fontSize: 12, color: '#cbd5e1', marginBottom: 6 }}>Auth setup status</div>
          {configLoading ? (
            <div style={{ fontSize: 12, color: '#94a3b8' }}>Checking backend config...</div>
          ) : (
            <div style={{ display: 'grid', gap: 4, fontSize: 12 }}>
              <div style={{ color: GOOGLE_CLIENT_ID ? '#34d399' : '#fca5a5' }}>
                {effectiveGoogleClientId ? 'OK' : 'Missing'} frontend: VITE_GOOGLE_CLIENT_ID
              </div>
              <div style={{ color: authConfig?.hasGoogleClientId ? '#34d399' : '#fca5a5' }}>
                {authConfig?.hasGoogleClientId ? 'OK' : 'Missing'} backend: GOOGLE_CLIENT_ID
              </div>
              <div style={{ color: authConfig?.hasAllowedAdminEmails ? '#34d399' : '#fca5a5' }}>
                {authConfig?.hasAllowedAdminEmails ? 'OK' : 'Missing'} backend: ADMIN_ALLOWED_EMAILS
              </div>
              <div style={{ color: authConfig?.has2FASecret ? '#34d399' : '#fca5a5' }}>
                {authConfig?.has2FASecret ? 'OK' : 'Missing'} backend: ADMIN_2FA_SECRET or ADMIN_2FA_SECRETS
              </div>
            </div>
          )}
        </div>

        {step === 'google' ? (
          <div>
            {!effectiveGoogleClientId ? (
              <div style={{ marginBottom: 12, color: '#fca5a5', fontSize: 13 }}>
                Missing Google client id. Set `VITE_GOOGLE_CLIENT_ID` in frontend env or configure backend `GOOGLE_CLIENT_ID`.
              </div>
            ) : null}
            <div ref={googleBtnRef} style={{ display: 'flex', justifyContent: 'center', marginBottom: 12 }} />
          </div>
        ) : (
          <>
            <div style={{ marginBottom: 8, color: '#93c5fd', fontSize: 13 }}>
              Signed in as: {email}
            </div>
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="Enter 6-digit 2FA code"
              style={{ width: '100%', padding: '10px 12px', borderRadius: 10, border: '1px solid rgba(148,163,184,.28)', background: 'rgba(2,6,23,.8)', color: '#f0f6ff', marginBottom: 12 }}
            />
            <button
              type="submit"
              disabled={loading || code.length !== 6}
              style={{ width: '100%', padding: '10px 12px', borderRadius: 10, border: 'none', background: '#22d3ee', color: '#02131d', fontWeight: 700, cursor: 'pointer' }}
            >
              {loading ? 'Verifying...' : 'Verify 2FA & Open Dashboard'}
            </button>
          </>
        )}

        <button
          type="button"
          onClick={() => navigate('/')}
          style={{ width: '100%', marginTop: 10, padding: '10px 12px', borderRadius: 10, border: '1px solid rgba(148,163,184,.28)', background: 'transparent', color: '#cbd5e1', cursor: 'pointer' }}
        >
          Back to Home
        </button>
      </form>
    </div>
  );
};

export default AdminLogin;
