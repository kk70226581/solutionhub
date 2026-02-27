// src/pages/AdminDashboard.jsx
import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';
import '../styles/AdminDashboard.css';

const AdminDashboard = () => {
  const [allExperts, setAllExperts] = useState([]);
  const [activeTab, setActiveTab] = useState('pending');
  const [isLoading, setIsLoading] = useState(false);
  const [onlineCount, setOnlineCount] = useState(0);
  const [message, setMessage] = useState({
    text: '',
    type: '',
    show: false,
  });
  const [modal, setModal] = useState({
    isOpen: false,
    src: '',
  });

  // Socket: online experts
  useEffect(() => {
    const socket = io();
    socket.on('online_users', users => {
      const count = Object.values(users || {}).filter(
        u => u.role === 'expert',
      ).length;
      setOnlineCount(count);
    });
    return () => socket.disconnect();
  }, []);

  // Toast helper
  const showToast = (text, type) => {
    setMessage({ text, type, show: true });
    setTimeout(
      () => setMessage(prev => ({ ...prev, show: false })),
      4000,
    );
  };

  // Fetch all expert lists and health
  const loadData = async () => {
    setIsLoading(true);
    try {
      const [pRes, aRes, rRes, hRes] = await Promise.all([
        fetch('/api/experts?status=pending'),
        fetch('/api/experts?status=approved'),
        fetch('/api/experts?status=rejected'),
        fetch('/api/health'),
      ]);

      const [p, a, r, h] = await Promise.all([
        pRes.json(),
        aRes.json(),
        rRes.json(),
        hRes.json(),
      ]);

      setAllExperts([...(p || []), ...(a || []), ...(r || [])]);
      if (h && typeof h.onlineExperts === 'number') {
        setOnlineCount(h.onlineExperts);
      }
    } catch (err) {
      console.error(err);
      showToast('Failed to connect to backend', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, []);

  // Update expert status
  const updateStatus = async (email, status) => {
    try {
      const res = await fetch('/api/admin/expert-status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, status }),
      });
      const data = await res.json();
      if (data.success) {
        showToast(`Status updated to ${status}`, 'success');
        loadData();
      } else {
        showToast(data.error || 'Update failed', 'error');
      }
    } catch (err) {
      console.error(err);
      showToast('Update failed', 'error');
    }
  };

  // Image modal
  const openModal = expert => {
    if (!expert.avatar) return;
    setModal({
      isOpen: true,
      src: `/${expert.avatar}`,
    });
  };

  const closeModal = () =>
    setModal(prev => ({ ...prev, isOpen: false }));

  const filteredExperts =
    activeTab === 'all'
      ? allExperts
      : allExperts.filter(e => e.status === activeTab);

  return (
    <div className="admin-dashboard">
      <div className="admin-shell">
        {/* Header */}
        <header className="admin-header">
          <div className="admin-header-top">
            <div>
              <h1 className="admin-title">
                <i className="fas fa-crown" />
                <span>Solvenut Admin</span>
              </h1>
              <p className="admin-subtitle">
                Review, approve, and monitor expert accounts in
                real-time.
              </p>
            </div>
            <button
              className="admin-refresh-btn"
              onClick={loadData}
              disabled={isLoading}
            >
              <i
                className={`fas ${
                  isLoading ? 'fa-spinner fa-spin' : 'fa-sync-alt'
                }`}
              />
              <span>{isLoading ? 'Refreshing…' : 'Refresh'}</span>
            </button>
          </div>

          {message.show && (
            <div
              className={`admin-toast admin-toast-${message.type}`}
            >
              {message.text}
            </div>
          )}
        </header>

        {/* Stats */}
        <section className="admin-stats-grid">
          <StatCard
            num={onlineCount}
            label="Live experts"
            color="online"
            icon="fa-circle"
          />
          <StatCard
            num={allExperts.filter(e => e.status === 'pending').length}
            label="Pending reviews"
            color="pending"
            icon="fa-clock"
          />
          <StatCard
            num={allExperts.filter(e => e.status === 'approved').length}
            label="Approved"
            color="approved"
            icon="fa-check-circle"
          />
          <StatCard
            num={allExperts.length}
            label="Total experts"
            color="total"
            icon="fa-users"
          />
        </section>

        {/* Tabs */}
        <section className="admin-tabs">
          {['pending', 'approved', 'rejected', 'all'].map(tab => (
            <button
              key={tab}
              className={`admin-tab-btn ${
                activeTab === tab ? 'active' : ''
              }`}
              onClick={() => setActiveTab(tab)}
            >
              {tab.toUpperCase()}
            </button>
          ))}
        </section>

        {/* Experts grid */}
        <main className="admin-expert-grid">
          {filteredExperts.length === 0 ? (
            <div className="admin-empty">
              <i className="fas fa-inbox" />
              <p>No experts in this bucket.</p>
            </div>
          ) : (
            filteredExperts.map(expert => (
              <article
                key={expert.email}
                className={`admin-expert-card admin-expert-${expert.status}`}
              >
                <div className="admin-expert-banner" />
                <button
                  className="admin-avatar-container"
                  onClick={() => openModal(expert)}
                  type="button"
                >
                  {expert.avatar ? (
                    <img
                      src={`/${expert.avatar}`}
                      className="admin-avatar-img"
                      alt={expert.name || 'Expert'}
                    />
                  ) : (
                    <div className="admin-avatar-fallback">
                      <i className="fas fa-user-circle" />
                    </div>
                  )}
                </button>

                <div className="admin-expert-header">
                  <h3 className="admin-expert-name">
                    {expert.name || 'Unnamed expert'}
                  </h3>
                  <p className="admin-expert-field">
                    {expert.field || 'No field specified'}
                  </p>
                  <p className="admin-expert-email">
                    {expert.email}
                  </p>
                </div>

                <div className="admin-expert-actions">
                  <button
                    className="admin-action-btn admin-approve-btn"
                    onClick={() =>
                      updateStatus(expert.email, 'approved')
                    }
                    disabled={expert.status === 'approved'}
                  >
                    Approve
                  </button>
                  <button
                    className="admin-action-btn admin-reject-btn"
                    onClick={() =>
                      updateStatus(expert.email, 'rejected')
                    }
                    disabled={expert.status === 'rejected'}
                  >
                    Reject
                  </button>
                </div>
              </article>
            ))
          )}
        </main>
      </div>

      {/* Image modal */}
      {modal.isOpen && (
        <div
          className="admin-modal-backdrop"
          onClick={closeModal}
        >
          <div
            className="admin-modal"
            onClick={e => e.stopPropagation()}
          >
            <img
              src={modal.src}
              alt="Expert"
              className="admin-modal-image"
            />
            <button
              className="admin-modal-close"
              onClick={closeModal}
              type="button"
            >
              <i className="fas fa-times" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

const StatCard = ({ num, label, color, icon }) => (
  <div className="admin-stat-card">
    <div className={`admin-stat-number admin-stat-${color}`}>
      {num}
    </div>
    <div className="admin-stat-label">
      <i className={`fas ${icon}`} />
      <span>{label}</span>
    </div>
  </div>
);

export default AdminDashboard;
