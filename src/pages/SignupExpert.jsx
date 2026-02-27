import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import '../styles/SignupExpert.css';

const SignupExpert = () => {
  const navigate = useNavigate();

  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [photoName, setPhotoName] = useState('');
  const [resumeName, setResumeName] = useState('');
  const [message, setMessage] = useState({ text: '', type: '' }); // type: 'success' | 'error' | ''
  const [isSubmitting, setIsSubmitting] = useState(false);

  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');
  const storedName =
    localStorage.getItem('name') ||
    localStorage.getItem('username') ||
    (localStorage.getItem('email')
      ? localStorage.getItem('email').split('@')[0]
      : null);

  const dashUrl = role === 'expert' ? '/expert-dashboard.html' : '/client-dashboard.html';

  // redirect if already logged in
  useEffect(() => {
    if (token && role) {
      navigate(dashUrl, { replace: true });
    }
  }, [token, role, dashUrl, navigate]);

  const handleLogout = () => {
    if (window.confirm('Logout from this device?')) {
      localStorage.clear();
      navigate('/login.html', { replace: true });
    }
  };

  const handleFileChange = (e, type) => {
    const file = e.target.files?.[0];
    const name = file ? `✓ ${file.name}` : '';
    if (type === 'photo') setPhotoName(name);
    if (type === 'resume') setResumeName(name);
  };

  const handleSubmit = async e => {
    e.preventDefault();
    if (isSubmitting) return;

    setMessage({ text: '', type: '' });

    const formEl = e.currentTarget;
    const formData = new FormData(formEl);

    const photo = formEl.photo.files[0];
    const resume = formEl.resume.files[0];

    // size checks (5MB)
    const maxSize = 5 * 1024 * 1024;
    if (photo && photo.size > maxSize) {
      setMessage({ text: 'Photo size must be less than 5MB', type: 'error' });
      return;
    }
    if (resume && resume.size > maxSize) {
      setMessage({ text: 'Resume size must be less than 5MB', type: 'error' });
      return;
    }

    setIsSubmitting(true);

    try {
      const res = await fetch('/api/pro-signup', {
        method: 'POST',
        body: formData,
      });

      const data = await res.json();

      if (data.success) {
        setMessage({
          text: 'Application submitted! Redirecting to login…',
          type: 'success',
        });
        setTimeout(() => {
          navigate('/login.html');
        }, 2000);
      } else {
        setMessage({
          text: data.error || 'Signup failed. Please try again.',
          type: 'error',
        });
        setIsSubmitting(false);
      }
    } catch (err) {
      setMessage({
        text: 'Server error. Please try again later.',
        type: 'error',
      });
      setIsSubmitting(false);
    }
  };

  const msgClass =
    message.type === ''
      ? 'msg'
      : `msg show ${message.type === 'success' ? 'success' : 'error'}`;

  return (
    <div className="signup-expert-page">
      {/* HEADER */}
      <header>
        <div className="container header-inner">
          <div className="logo" onClick={() => navigate('/')}>
            <div className="mark">🥜</div>
            <div className="txt">
              Solve<span className="nut">nut</span>
            </div>
          </div>

          <nav className="desktop">
            <a href="/#categories">Categories</a>
            <a href="/#how">How It Works</a>
            <a href="/#features">Features</a>
            <Link to="/experts">Find Experts</Link>
          </nav>

          <div className="actions">
            {token && role ? (
              <>
                <div className="nav-user-pill">
                  <i className="fa-regular fa-circle-user"></i>
                  <span>{storedName || 'User'}</span>
                </div>
                <Link
                  className="btn btn-ghost"
                  to={dashUrl}
                  style={{ fontSize: '13px', padding: '6px 12px' }}
                >
                  Dashboard
                </Link>
                <button className="nav-logout" onClick={handleLogout}>
                  Logout
                </button>
              </>
            ) : (
              <Link className="btn btn-ghost" to="/login.html">
                Log in
              </Link>
            )}
          </div>

          <button
            className="mobile-toggle"
            aria-expanded={isMenuOpen}
            aria-controls="mobileDrawer"
            onClick={() => setIsMenuOpen(true)}
          >
            <i className="fa-solid fa-bars"></i>
          </button>
        </div>
      </header>

      {/* MOBILE DRAWER */}
      <div
        id="mobileDrawer"
        className={`mobile-drawer ${isMenuOpen ? 'open' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-hidden={!isMenuOpen}
        style={{ display: isMenuOpen ? 'flex' : 'none' }}
      >
        <button
          style={{
            alignSelf: 'flex-end',
            background: 'transparent',
            border: 0,
            color: 'var(--text)',
            fontSize: '24px',
            padding: '6px',
            cursor: 'pointer',
          }}
          onClick={() => setIsMenuOpen(false)}
        >
          <i className="fa-solid fa-xmark"></i>
        </button>
        <a href="/#categories" onClick={() => setIsMenuOpen(false)}>
          Categories
        </a>
        <a href="/#how" onClick={() => setIsMenuOpen(false)}>
          How It Works
        </a>
        <a href="/#features" onClick={() => setIsMenuOpen(false)}>
          Features
        </a>
        <Link to="/experts" onClick={() => setIsMenuOpen(false)}>
          Find Experts
        </Link>
      </div>

      {/* MAIN */}
      <main>
        <div className="container">
          <div className="expert-card">
            <div className="header-top">
              <h2>Join Solvenut as an expert</h2>
              <p>
                Share your knowledge, earn per session, and help people make better decisions every
                day.
              </p>
            </div>

            <form id="proSignupForm" onSubmit={handleSubmit} encType="multipart/form-data">
              {/* Personal */}
              <div className="form-section">
                <div className="section-title">
                  <i className="fas fa-user"></i>
                  Personal details
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="name" className="required">
                      Full name
                    </label>
                    <input
                      id="name"
                      type="text"
                      name="name"
                      placeholder="Your full name"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label htmlFor="email" className="required">
                      Email address
                    </label>
                    <input
                      id="email"
                      type="email"
                      name="email"
                      placeholder="you@example.com"
                      required
                    />
                  </div>
                </div>
                <div className="form-group">
                  <label htmlFor="password" className="required">
                    Password
                  </label>
                  <input
                    id="password"
                    type="password"
                    name="password"
                    placeholder="Minimum 6 characters"
                    minLength={6}
                    required
                  />
                </div>
              </div>

              {/* Professional */}
              <div className="form-section">
                <div className="section-title">
                  <i className="fas fa-briefcase"></i>
                  Professional profile
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="field" className="required">
                      Domain / field
                    </label>
                    <select id="field" name="field" required>
                      <option value="">Select your domain</option>
                      <option value="Programming">Programming</option>
                      <option value="DevOps">DevOps & Cloud</option>
                      <option value="Academics">Academics & Teaching</option>
                      <option value="Medical">Medical & Healthcare</option>
                      <option value="Engineering">Engineering</option>
                      <option value="Business">Business & Management</option>
                      <option value="Career">Career Counseling</option>
                      <option value="Legal">Legal & Law</option>
                      <option value="Finance">Finance & Accounting</option>
                      <option value="Design">Design & Creative</option>
                      <option value="Marketing">Marketing & Sales</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label htmlFor="experience" className="required">
                      Years of experience
                    </label>
                    <input
                      id="experience"
                      type="number"
                      name="experience"
                      min="0"
                      max="50"
                      placeholder="5"
                      required
                    />
                  </div>
                </div>
                <div className="form-group">
                  <label htmlFor="headline" className="required">
                    Professional headline
                  </label>
                  <input
                    id="headline"
                    type="text"
                    name="headline"
                    placeholder="Senior Full‑Stack Developer | React & Node.js"
                    maxLength={100}
                    required
                  />
                  <small>A short tagline about your expertise (max 100 characters)</small>
                </div>
                <div className="form-group">
                  <label htmlFor="summary" className="required">
                    Professional summary
                  </label>
                  <textarea
                    id="summary"
                    name="summary"
                    placeholder="Describe your experience, skills, and what you can help Solvenut clients with..."
                    maxLength={500}
                    required
                  ></textarea>
                  <small>Detailed summary of your background and services (max 500 characters)</small>
                </div>
                <div className="form-group">
                  <label htmlFor="linkedin">LinkedIn profile (optional)</label>
                  <input
                    id="linkedin"
                    type="url"
                    name="linkedin"
                    placeholder="https://linkedin.com/in/yourprofile"
                  />
                  <small>Add your LinkedIn URL to help us verify your profile faster</small>
                </div>
              </div>

              {/* Pricing */}
              <div className="form-section">
                <div className="section-title">
                  <i className="fas fa-rupee-sign"></i>
                  Consultation fee
                </div>
                <div className="form-group">
                  <label htmlFor="price" className="required">
                    Consultation fee (per session)
                  </label>
                  <div className="price-input">
                    <input
                      id="price"
                      type="number"
                      name="price"
                      min="100"
                      max="10000"
                      placeholder="500"
                      required
                    />
                  </div>
                  <small>
                    Set your fee in INR (₹100 – ₹10,000 per session). You can change this later.
                  </small>
                </div>
              </div>

              {/* Documents */}
              <div className="form-section">
                <div className="section-title">
                  <i className="fas fa-file-upload"></i>
                  Documents & verification
                </div>
                <div className="form-group">
                  <label htmlFor="photo" className="required">
                    Profile photo
                  </label>
                  <div className="file-input-wrapper">
                    <input
                      id="photo"
                      type="file"
                      name="photo"
                      accept="image/jpeg,image/png,image/jpg"
                      required
                      onChange={e => handleFileChange(e, 'photo')}
                    />
                    <label htmlFor="photo" className="file-input-label">
                      <i className="fas fa-camera"></i>
                      <span>Choose profile photo</span>
                    </label>
                  </div>
                  {photoName && <span className="file-name">{photoName}</span>}
                  <small>Upload a clear, professional photo (JPG/PNG, max 5MB).</small>
                </div>
                <div className="form-group">
                  <label htmlFor="resume" className="required">
                    Resume / CV (PDF)
                  </label>
                  <div className="file-input-wrapper">
                    <input
                      id="resume"
                      type="file"
                      name="resume"
                      accept=".pdf"
                      required
                      onChange={e => handleFileChange(e, 'resume')}
                    />
                    <label htmlFor="resume" className="file-input-label">
                      <i className="fas fa-file-pdf"></i>
                      <span>Choose resume (PDF)</span>
                    </label>
                  </div>
                  {resumeName && <span className="file-name">{resumeName}</span>}
                  <small>Upload your latest resume in PDF format (max 5MB).</small>
                </div>
              </div>

              <button type="submit" id="submitBtn" disabled={isSubmitting}>
                {isSubmitting ? (
                  <>
                    <i className="fas fa-spinner fa-spin"></i> Submitting your application…
                  </>
                ) : (
                  <>
                    <i className="fas fa-user-plus"></i> Apply as Solvenut expert
                  </>
                )}
              </button>
            </form>

            <div id="message" className={msgClass}>
              {message.text && (
                <>
                  {message.type === 'success' ? (
                    <i className="fas fa-check-circle"></i>
                  ) : (
                    <i className="fas fa-exclamation-circle"></i>
                  )}{' '}
                  {message.text}
                </>
              )}
            </div>

            <div className="footer">
              Already have an account? <Link to="/login.html">Log in</Link>
            </div>
          </div>
        </div>
      </main>

      {/* PAGE FOOTER */}
      <footer className="page-footer">
        <div className="container footer-inner">
          <div>© 2026 Solvenut. Experts are manually reviewed before going live.</div>
          <div className="footer-links">
            <a href="#">Privacy</a>
            <a href="#">Terms</a>
            <a href="#">Support</a>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default SignupExpert;
