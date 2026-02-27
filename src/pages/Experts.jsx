// src/pages/Experts.jsx
import React, { useState, useEffect } from 'react';
import {
  Link,
  useNavigate,
  createSearchParams,
} from 'react-router-dom';
import '../styles/Experts.css';

// ✅ Use env-based API root, e.g. VITE_API_BASE=https://solutionhub66.onrender.com
const API = import.meta.env.VITE_API_BASE;

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

  // Auth info (for header + Razorpay prefill)
  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');
  const storedName =
    localStorage.getItem('name') ||
    localStorage.getItem('username') ||
    'User';
  const userEmail = localStorage.getItem('email');

  // Load experts list
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

    if (API) fetchExperts();
  }, []);

  // Apply filters/search/sort
  useEffect(() => {
    let list = [...experts];

    // Filter
    if (activeFilter !== 'all') {
      list = list.filter(e =>
        (e.field || '')
          .toLowerCase()
          .includes(activeFilter.toLowerCase()),
      );
    }

    // Search
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      list = list.filter(e =>
        (e.name || '').toLowerCase().includes(q) ||
        (e.field || '').toLowerCase().includes(q) ||
        (e.headline || '').toLowerCase().includes(q),
      );
    }

    // Sort
    list.sort((a, b) => {
      if (sortBy === 'rating') {
        const ra = a.rating || 0;
        const rb = b.rating || 0;
        return rb - ra;
      }
      if (sortBy === 'price-low') {
        const pa = a.price || 500;
        const pb = b.price || 500;
        return pa - pb;
      }
      if (sortBy === 'price-high') {
        const pa = a.price || 500;
        const pb = b.price || 500;
        return pb - pa;
      }
      if (sortBy === 'experience') {
        const ea = a.experience || 0;
        const eb = b.experience || 0;
        return eb - ea;
      }
      return 0;
    });

    setFilteredExperts(list);
  }, [experts, activeFilter, searchTerm, sortBy]);

  // Load Razorpay script once
  useEffect(() => {
    const scriptId = 'razorpay-checkout';
    if (document.getElementById(scriptId)) return;

    const script = document.createElement('script');
    script.id = scriptId;
    script.src = 'https://checkout.razorpay.com/v1/checkout.js';
    script.async = true;
    script.onload = () => console.log('Razorpay script loaded');
    script.onerror = () => console.error('Failed to load Razorpay script');
    document.body.appendChild(script);
  }, []);

  // ✅ Build photo URL from backend origin (API) instead of window.location
  const getPhotoUrl = expert => {
    const avatar = expert?.avatar;
    if (!avatar || !API) return null;
    if (avatar.startsWith('http')) return avatar;
    const base = API; // e.g. https://solutionhub66.onrender.com
    return `${base}/${avatar.replace(/^\/+/, '')}`;
  };

  // Razorpay payment flow
  const handlePayment = async expert => {
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
        console.error('Create-order failed:', orderRes.status, errBody);
        throw new Error(errBody.error || 'Order creation failed');
      }

      const orderData = await orderRes.json();
      setIsProcessingPayment(false);

      if (!window.Razorpay || typeof window.Razorpay !== 'function') {
        console.error('window.Razorpay not available:', window.Razorpay);
        alert('Payment service is still loading. Please try again in a moment.');
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
        handler: async response => {
          verifyPayment(response, expert);
        },
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
      console.log('verify-payment response:', verifyRes.status, data);

      setIsProcessingPayment(false);

      if (data.success) {
        alert(`Success! You can now talk to ${expert.name}.`);

        // Navigate to chat with email + paymentId as query params
        navigate({
          pathname: '/chat',
          search: `?${createSearchParams({
            email: expert.email,
            paymentId: data.paymentId,
          }).toString()}`,
        });
      } else {
        throw new Error(data.error || 'Verification failed');
      }
    } catch (e) {
      console.error('Payment verification error:', e);
      setIsProcessingPayment(false);
      alert('Payment verification failed.');
    }
  };

  const dashUrl = role === 'expert' ? '/expert-dashboard' : '/client-dashboard';

  return (
    <div className="experts-page">
      <div className="ambient-bg" aria-hidden="true"></div>

      {/* HEADER */}
      <header className="experts-header">
        <div className="container header-inner">
          <div className="logo" onClick={() => navigate('/')}>
            <div className="logo-mark">🥜</div>
            <div className="logo-text">
              <span className="logo-title">Solvenut</span>
              <span className="logo-sub">Experts marketplace</span>
            </div>
          </div>

          <nav className="nav-desktop">
            <Link to="/">Home</Link>
            <Link to="/experts" className="active">
              Find Experts
            </Link>
          </nav>

          <div className="header-right">
            {token ? (
              <>
                <div className="header-user">
                  <div className="header-avatar">
                    {storedName ? storedName[0] : 'U'}
                  </div>
                  <div className="header-user-info">
                    <span className="header-user-name">Hi, {storedName}</span>
                    <span className="header-user-role">
                      {role === 'expert' ? 'Expert' : 'Client'}
                    </span>
                  </div>
                </div>
                <Link
                  to={dashUrl}
                  className="btn btn-outline-sm"
                >
                  Dashboard
                </Link>
              </>
            ) : (
              <>
                <Link to="/login" className="btn btn-ghost-sm">
                  Login
                </Link>
                <Link to="/signup-client" className="btn btn-primary-sm">
                  Create free account
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* MAIN */}
      <main className="experts-main">
        <div className="container">
          {/* HERO, controls etc. (same as before) */}

          {/* GRID */}
          <section className="experts-grid">
            {isLoading ? (
              <div className="state state-loading">
                <i className="fa-solid fa-spinner fa-spin"></i>
                <span>Loading experts...</span>
              </div>
            ) : filteredExperts.length === 0 ? (
              <div className="state state-empty">
                <i className="fa-regular fa-face-frown"></i>
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
                <article key={idx} className="expert-card">
                  <div className="card-top">
                    <div className="card-avatar">
                      {getPhotoUrl(expert) ? (
                        <img
                          src={getPhotoUrl(expert)}
                          alt={expert.name}
                        />
                      ) : (
                        (expert.name || 'E')[0]
                      )}
                    </div>
                    <div className="card-main">
                      <h3>{expert.name}</h3>
                      <p className="card-field">{expert.field}</p>
                      <div className="card-meta">
                        <span>
                          ⭐ {expert.rating || 4.9}{' '}
                          <span className="muted">
                            ({expert.reviews || 0} reviews)
                          </span>
                        </span>
                        <span>•</span>
                        <span>
                          {expert.experience || 1}+ yrs experience
                        </span>
                      </div>
                    </div>
                  </div>

                  <p className="card-headline">
                    {expert.headline ||
                      'Helping people with practical, easy-to-follow guidance.'}
                  </p>

                  <div className="card-tags">
                    {expert.skills &&
                      Array.isArray(expert.skills) &&
                      expert.skills.slice(0, 3).map((tag, i) => (
                        <span key={i} className="tag">
                          {tag}
                        </span>
                      ))}
                    {!expert.skills && (
                      <>
                        <span className="tag">Quick replies</span>
                        <span className="tag">Detailed explanations</span>
                      </>
                    )}
                  </div>

                  <div className="card-bottom">
                    <div className="card-price-block">
                      <span className="price-main">
                        ₹{expert.price || 500}
                      </span>
                      <span className="price-sub">per session (prepaid)</span>
                    </div>
                    <button
                      className="btn btn-primary-sm"
                      onClick={() => handlePayment(expert)}
                    >
                      Pay & talk
                    </button>
                  </div>
                </article>
              ))
            )}
          </section>
        </div>
      </main>

      {/* PAYMENT MODAL */}
      {isProcessingPayment && (
        <div className="payment-modal">
          <div className="payment-box">
            <i className="fa-solid fa-spinner fa-spin"></i>
            <p>Initializing secure payment…</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default Experts;
