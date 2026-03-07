import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const API = import.meta.env.VITE_API_BASE || 'https://solutionhub66.onrender.com';

const AdminLogin = () => {
  const navigate = useNavigate();
  const [secret, setSecret] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!secret.trim() || loading) return;

    setLoading(true);
    try {
      const res = await fetch(`${API}/api/health`, {
        headers: { 'x-admin-token': secret.trim() },
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data?.error) {
        alert(data?.error || 'Invalid admin credentials');
        setLoading(false);
        return;
      }

      localStorage.setItem('adminToken', secret.trim());
      navigate('/admin-dashboard');
    } catch {
      alert('Failed to reach admin API');
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', background: '#030712', color: '#f0f6ff', display: 'grid', placeItems: 'center', padding: 16 }}>
      <form onSubmit={handleLogin} style={{ width: '100%', maxWidth: 420, background: 'rgba(9,16,36,.92)', border: '1px solid rgba(148,163,184,.22)', borderRadius: 14, padding: 20 }}>
        <h2 style={{ marginBottom: 8 }}>Admin Login</h2>
        <p style={{ marginBottom: 14, color: '#94a3b8', fontSize: 14 }}>Use your admin secret key to open admin dashboard.</p>
        <input
          type="password"
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          placeholder="Admin secret key"
          style={{ width: '100%', padding: '10px 12px', borderRadius: 10, border: '1px solid rgba(148,163,184,.28)', background: 'rgba(2,6,23,.8)', color: '#f0f6ff', marginBottom: 12 }}
        />
        <button
          type="submit"
          disabled={loading || !secret.trim()}
          style={{ width: '100%', padding: '10px 12px', borderRadius: 10, border: 'none', background: '#22d3ee', color: '#02131d', fontWeight: 700, cursor: 'pointer' }}
        >
          {loading ? 'Checking...' : 'Open Admin Dashboard'}
        </button>
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
