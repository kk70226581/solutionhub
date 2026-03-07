// src/App.jsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

import Home from './pages/Home';
import FancyHome from './pages/FancyHome';
import Experts from './pages/Experts';
import AdminDashboard from './pages/AdminDashboard';
import AdminLogin from './pages/AdminLogin';
import ClientChat from './pages/ClientChat';
import ClientDashboard from './pages/ClientDashboard';
import ExpertDashboard from './pages/ExpertDashboard';
import Login from './pages/Login';
import SignupClient from './pages/SignupClient';
import SignupExpert from './pages/SignupExpert';

function App() {
  return (
    <Router>
      <Routes>
        {/* public */}
        <Route path="/" element={<Home />} />
        <Route path="/fancy" element={<FancyHome />} />
        <Route path="/experts" element={<Experts />} />

        {/* auth */}
        <Route path="/login" element={<Login />} />
        <Route path="/signup-client" element={<SignupClient />} />
        <Route path="/signup-expert" element={<SignupExpert />} />

        {/* client side */}
        <Route path="/client-dashboard" element={<ClientDashboard />} />
        <Route path="/chat" element={<ClientChat />} />

        {/* expert side */}
        <Route path="/expert-dashboard" element={<ExpertDashboard />} />

        {/* admin */}
        <Route path="/admin-login" element={<AdminLogin />} />
        <Route path="/admin-dashboard" element={<AdminDashboard />} />

        {/* optional: small placeholder so /pricing warning goes away */}
        <Route path="/pricing" element={<div>Pricing coming soon…</div>} />
      </Routes>
    </Router>
  );
}

export default App;
