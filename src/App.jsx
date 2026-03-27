// src/App.jsx
import React from 'react';
import { BrowserRouter, HashRouter, Routes, Route } from 'react-router-dom';

import Home from './pages/Home';
import Experts from './pages/Experts';
import AdminDashboard from './pages/AdminDashboard';
import AdminLogin from './pages/AdminLogin';
import ClientChat from './pages/ClientChat';
import ClientDashboard from './pages/ClientDashboard';
import ExpertDashboard from './pages/ExpertDashboard';
import Login from './pages/Login';
import SignupClient from './pages/SignupClient';
import SignupExpert from './pages/SignupExpert';
import ProtectedRoute from './components/ProtectedRoute';
import GlobalCallNotifier from './components/GlobalCallNotifier';

function App() {
  // HashRouter in production prevents refresh 404 on hosts without SPA rewrites.
  const Router = import.meta.env.PROD ? HashRouter : BrowserRouter;

  return (
    <Router>
      <Routes>
        {/* public */}
        <Route path="/" element={<Home />} />
        <Route path="/experts" element={<Experts />} />

        {/* auth */}
        <Route path="/login" element={<Login />} />
        <Route path="/signup-client" element={<SignupClient />} />
        <Route path="/signup-expert" element={<SignupExpert />} />

        {/* client side */}
        <Route element={<ProtectedRoute allowedRoles={['client']} redirectTo="/login" />}>
          <Route path="/client-dashboard" element={<ClientDashboard />} />
          <Route path="/chat" element={<ClientChat />} />
        </Route>

        {/* expert side */}
        <Route element={<ProtectedRoute allowedRoles={['expert']} redirectTo="/login" />}>
          <Route path="/expert-dashboard" element={<ExpertDashboard />} />
        </Route>

        {/* admin */}
        <Route path="/admin-login" element={<AdminLogin />} />
        <Route
          element={
            <ProtectedRoute
              tokenKey="adminSessionToken"
              roleKey={null}
              redirectTo="/admin-login"
            />
          }
        >
          <Route path="/admin-dashboard" element={<AdminDashboard />} />
        </Route>

        <Route path="/pricing" element={<div>Pricing coming soon...</div>} />
        <Route path="*" element={<Home />} />
      </Routes>
      <GlobalCallNotifier />
    </Router>
  );
}

export default App;
