// src/pages/FancyHome.jsx
import React from 'react';
import '../styles/FancyHome.css';

const FancyHome = () => {
  return (
    <div className="fancy-home-page">
      <div className="home-page-bg" />
      <main className="home-main">
        <div className="fancy-home-shell">
          {/* Put your old Home JSX here that used .home-page / .home-shell / .home-why-card etc. */}
        </div>
      </main>
    </div>
  );
};

export default FancyHome;
