import React, { useEffect, useMemo, useState } from 'react';
import { Link, createSearchParams, useNavigate } from 'react-router-dom';
import '../styles/Experts.css';

const API = import.meta.env.VITE_API_BASE || 'http://localhost:3000';

const FILTERS = [
  { id: 'all', label: 'All experts' },
  { id: 'programming', label: 'Programming' },
  { id: 'devops', label: 'DevOps' },
  { id: 'academics', label: 'Academics' },
  { id: 'career', label: 'Career' },
  { id: 'business', label: 'Business' },
  { id: 'medical', label: 'Medical' },
];

const Experts = () => {
  const navigate = useNavigate();

  const [experts, setExperts] = useState([]);
  const [filteredExperts, setFilteredExperts] = useState([]);
  const [activeFilter, setActiveFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState('rating');
  const [isLoading, setIsLoading] = useState(true);
  const [isProcessingPayment, setIsProcessingPayment] = useState(false);
  const [checkingChatFor, setCheckingChatFor] = useState('');

  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');
  const storedName =
    localStorage.getItem('name') || localStorage.getItem('username') || 'User';
  const userEmail = localStorage.getItem('email');

  useEffect(() => {
    const fetchExperts = async () => {
      try {
        setIsLoading(true);
        const res = await fetch(`${API}/api/experts?status=approved`);
        if (!res.ok) throw new Error('Failed to load experts');
        const data = await res.json();
        setExperts(Array.isArray(data) ? data : []);
      } catch (err) {
        console.error(err);
        setExperts([]);
      } finally {
        setIsLoading(false);
      }
    };

    fetchExperts();
  }, []);

  useEffect(() => {
    let list = [...experts];

    if (activeFilter !== 'all') {
      list = list.filter((e) =>
        (e.field || '').toLowerCase().includes(activeFilter.toLowerCase()),
      );
    }

    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      list = list.filter(
        (e) =>
          (e.name || '').toLowerCase().includes(q) ||
          (e.field || '').toLowerCase().includes(q) ||
          (e.headline || '').toLowerCase().includes(q),
      );
    }

    list.sort((a, b) => {
      if (sortBy === 'rating') return (b.rating || 0) - (a.rating || 0);
      if (sortBy === 'price-low') return (a.price || 500) - (b.price || 500);
      if (sortBy === 'price-high') return (b.price || 500) - (a.price || 500);
      if (sortBy === 'experience')
        return (b.experience || 0) - (a.experience || 0);
      return 0;
    });

    setFilteredExperts(list);
  }, [experts, activeFilter, searchTerm, sortBy]);

  useEffect(() => {
    const scriptId = 'razorpay-checkout';
    if (document.getElementById(scriptId)) return;
    const script = document.createElement('script');
    script.id = scriptId;
    script.src = 'https://checkout.razorpay.com/v1/checkout.js';
    script.async = true;
    document.body.appendChild(script);
  }, []);

  const getPhotoUrl = (expert) => {
    const avatar = expert?.avatar;
    if (!avatar) return null;
    if (avatar.startsWith('http')) return avatar;
    return `${API}/${avatar.replace(/^\/+/, '')}`;
  };

  const handlePayment = async (expert) => {
    const freshToken = localStorage.getItem('token');
    if (!freshToken) {
      alert('Please login first.');
      navigate('/login');
      return;
    }

    try {
      setIsProcessingPayment(true);
      const orderRes = await fetch(`${API}/api/create-order`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${freshToken}`,
        },
        body: JSON.stringify({
          expertEmail: expert.email,
          expertField: expert.field,
        }),
      });

      if (!orderRes.ok) {
        const errBody = await orderRes.json().catch(() => ({}));
        throw new Error(errBody.error || 'Order creation failed');
      }

      const orderData = await orderRes.json();
      setIsProcessingPayment(false);

      if (!window.Razorpay || typeof window.Razorpay !== 'function') {
        alert('Payment service is still loading. Please try again.');
        return;
      }

      const options = {
        key: orderData.key,
        amount: orderData.amount,
        currency: orderData.currency,
        name: 'Solvenut',
        description: `Consultation with ${expert.name}`,
        order_id: orderData.orderId,
        prefill: { name: storedName, email: userEmail },
        handler: async (response) => verifyPayment(response, expert),
      };

      const rzp = new window.Razorpay(options);
      rzp.open();
    } catch (e) {
      console.error('Payment init error:', e);
      setIsProcessingPayment(false);
      alert(e.message || 'Payment failed to initialize.');
    }
  };

  const verifyPayment = async (paymentResponse, expert) => {
    try {
      setIsProcessingPayment(true);
      const freshToken = localStorage.getItem('token');
      const verifyRes = await fetch(`${API}/api/verify-payment`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${freshToken}`,
        },
        body: JSON.stringify({
          razorpay_order_id: paymentResponse.razorpay_order_id,
          razorpay_payment_id: paymentResponse.razorpay_payment_id,
          razorpay_signature: paymentResponse.razorpay_signature,
        }),
      });

      const data = await verifyRes.json();
      setIsProcessingPayment(false);

      if (!data.success) throw new Error(data.error || 'Verification failed');
      alert(`Success! You can now talk to ${expert.name}.`);
      navigate({
        pathname: '/chat',
        search: `?${createSearchParams({
          email: expert.email,
          paymentId: data.paymentId,
        }).toString()}`,
      });
    } catch (e) {
      console.error('Payment verification error:', e);
      setIsProcessingPayment(false);
      alert('Payment verification failed.');
    }
  };

  const handleChatNow = async (expert) => {
    const freshToken = localStorage.getItem('token');
    if (!freshToken) {
      alert('Please login first.');
      navigate('/login');
      return;
    }

    try {
      setCheckingChatFor(expert.email || '');
      const res = await fetch(
        `${API}/api/check-payment?expertEmail=${encodeURIComponent(expert.email || '')}`,
        {
          headers: { Authorization: `Bearer ${freshToken}` },
        },
      );
      const data = await res.json().catch(() => ({}));
      if (res.ok && data?.hasPaid && data?.payment?.paymentId) {
        navigate({
          pathname: '/chat',
          search: `?${createSearchParams({
            email: expert.email,
            paymentId: data.payment.paymentId,
          }).toString()}`,
        });
        return;
      }
      alert('Please complete payment first to unlock chat with this expert.');
    } catch (err) {
      console.error('Chat access check failed:', err);
      alert('Unable to verify chat access right now. Please try again.');
    } finally {
      setCheckingChatFor('');
    }
  };

  const dashUrl = role === 'expert' ? '/expert-dashboard' : '/client-dashboard';
  const avgPrice = useMemo(() => {
    if (!experts.length) return 0;
    const total = experts.reduce((acc, e) => acc + Number(e.price || 500), 0);
    return Math.round(total / experts.length);
  }, [experts]);

  return (
    <div className="experts-page">
      <div className="ambient-bg" aria-hidden />

      <header className="experts-header">
        <div className="container header-inner">
          <button className="logo" onClick={() => navigate('/')} aria-label="Home">
            <div className="logo-mark">🥜</div>
            <div className="logo-text">
              <span className="logo-title">
                Solve<span className="logo-title-nut">nut</span>
              </span>
              <span className="logo-sub">Experts marketplace</span>
            </div>
          </button>

          <nav className="nav-desktop">
            <Link to="/">Home</Link>
            <Link to="/experts" className="active">
              Experts
            </Link>
            <Link to="/client-dashboard">Client dashboard</Link>
          </nav>

          <div className="header-right">
            {token ? (
              <>
                <div className="header-user">
                  <div className="header-avatar">{storedName[0] || 'U'}</div>
                  <div className="header-user-info">
                    <span className="header-user-name">{storedName}</span>
                    <span className="header-user-role">
                      {role === 'expert' ? 'Expert' : 'Client'}
                    </span>
                  </div>
                </div>
                <Link to={dashUrl} className="btn btn-outline-sm">
                  Dashboard
                </Link>
              </>
            ) : (
              <>
                <Link to="/login" className="btn btn-ghost-sm">
                  Log in
                </Link>
                <Link to="/signup-client" className="btn btn-primary-sm">
                  Get started
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      <main className="experts-main">
        <div className="container">
          <section className="experts-hero">
            <div className="hero-left">
              <p className="hero-kicker">Choose expert support</p>
              <h1>Find the right expert and solve your problem faster.</h1>
              <p>
                Compare experts by domain, experience, rating, and session fees.
                Start chat securely once your booking is complete.
              </p>
            </div>
            <aside className="hero-right">
              <div className="hero-summary">
                <div className="hero-stat">
                  <span className="hero-stat-label">Experts</span>
                  <span className="hero-stat-value">{experts.length}</span>
                </div>
                <div className="hero-stat">
                  <span className="hero-stat-label">Average fee</span>
                  <span className="hero-stat-value">₹{avgPrice || 500}</span>
                </div>
                <div className="hero-stat">
                  <span className="hero-stat-label">Support</span>
                  <span className="hero-stat-value">Private chat</span>
                </div>
              </div>
            </aside>
          </section>

          <section className="experts-controls">
            <div className="filters-group">
              <div className="filters-label">Filter by domain</div>
              <div className="filters-pills">
                {FILTERS.map((f) => (
                  <button
                    key={f.id}
                    className={`filter-pill ${activeFilter === f.id ? 'active' : ''}`}
                    onClick={() => setActiveFilter(f.id)}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            </div>
            <div className="controls-right">
              <div className="search-box">
                <span>🔎</span>
                <input
                  placeholder="Search name, field, headline"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
              <div className="sort-box">
                <label>Sort</label>
                <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
                  <option value="rating">Top rated</option>
                  <option value="price-low">Price: low to high</option>
                  <option value="price-high">Price: high to low</option>
                  <option value="experience">Most experienced</option>
                </select>
              </div>
            </div>
          </section>

          <div className="results-meta">
            Showing {filteredExperts.length} of {experts.length} experts
          </div>

          <section className="experts-grid">
            {isLoading ? (
              <div className="state state-loading">Loading experts...</div>
            ) : filteredExperts.length === 0 ? (
              <div className="state state-empty">
                <p>No experts found with your filters.</p>
                <button
                  className="btn btn-outline-sm"
                  onClick={() => {
                    setActiveFilter('all');
                    setSearchTerm('');
                    setSortBy('rating');
                  }}
                >
                  Clear filters
                </button>
              </div>
            ) : (
              filteredExperts.map((expert, idx) => (
                <article key={`${expert.email || expert.name}-${idx}`} className="expert-card">
                  <div className="card-top">
                    <div className="card-avatar">
                      {getPhotoUrl(expert) ? (
                        <img src={getPhotoUrl(expert)} alt={expert.name} />
                      ) : (
                        (expert.name || 'E')[0]
                      )}
                    </div>

                    <div className="card-main">
                      <h3>{expert.name}</h3>
                      <p className="card-field">{expert.field || 'General Guidance'}</p>
                      <div className="card-meta">
                        <span>⭐ {expert.rating || 4.9}</span>
                        <span>•</span>
                        <span>{expert.experience || 1}+ yrs exp</span>
                      </div>
                    </div>
                  </div>

                  <p className="card-headline">
                    {expert.headline ||
                      'Practical guidance tailored to your context and goals.'}
                  </p>

                  <div className="card-tags">
                    {expert.skills && Array.isArray(expert.skills) ? (
                      expert.skills.slice(0, 3).map((tag, i) => (
                        <span key={i} className="tag">
                          {tag}
                        </span>
                      ))
                    ) : (
                      <>
                        <span className="tag">Actionable advice</span>
                        <span className="tag">Fast response</span>
                      </>
                    )}
                  </div>

                  <div className="card-bottom">
                    <div className="card-price-block">
                      <span className="price-main">₹{expert.price || 500}</span>
                      <span className="price-sub">per session</span>
                    </div>
                    <div className="card-actions">
                      <button
                        className="btn btn-outline-sm"
                        onClick={() => handleChatNow(expert)}
                        disabled={checkingChatFor === (expert.email || '')}
                      >
                        {checkingChatFor === (expert.email || '') ? 'Checking...' : 'Chat now'}
                      </button>
                      <button className="btn btn-primary-sm" onClick={() => handlePayment(expert)}>
                        Pay & talk
                      </button>
                    </div>
                  </div>
                </article>
              ))
            )}
          </section>
        </div>
      </main>

      <footer className="experts-footer">
        <div className="container experts-footer-row">
          <div className="experts-footer-left">
            <div className="experts-footer-brand">
              <span className="experts-footer-logo">🥜</span>
              <span className="experts-footer-name">Solvenut</span>
            </div>
            <p>
              Solvenut connects clients with experts to solve important problems
              through practical guidance.
            </p>
          </div>
          <div className="experts-footer-links">
            <button onClick={() => navigate('/')}>Home</button>
            <button onClick={() => navigate('/client-dashboard')}>Client dashboard</button>
            <button onClick={() => navigate('/signup-client')}>Join as client</button>
            <button onClick={() => navigate('/signup-expert')}>Join as expert</button>
          </div>
        </div>
      </footer>

      {isProcessingPayment && (
        <div className="payment-modal">
          <div className="payment-box">Initializing secure payment...</div>
        </div>
      )}
    </div>
  );
};

export default Experts;
