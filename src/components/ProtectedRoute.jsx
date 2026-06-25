import React, { useState } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';

const parseJwtPayload = (token) => {
  try {
    const payload = token.split('.')[1];
    if (!payload) return null;
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`)
        .join('')
    );
    return JSON.parse(json);
  } catch {
    return null;
  }
};

const getTokenAuthState = (tokenKey) => {
  const token = localStorage.getItem(tokenKey);
  if (!token) {
    return { valid: false };
  }

  const payload = parseJwtPayload(token);
  if (!payload?.exp || payload.exp * 1000 <= Date.now()) {
    localStorage.removeItem(tokenKey);
    return { valid: false };
  }

  return { valid: true };
};

function ProtectedRoute({
  redirectTo = '/login',
  tokenKey = 'token',
  roleKey = 'role',
  allowedRoles = null,
}) {
  const [authState] = useState(() => getTokenAuthState(tokenKey));
  const location = useLocation();
  const redirectState = { from: `${location.pathname}${location.search}` };

  if (!authState.valid) return <Navigate to={redirectTo} replace state={redirectState} />;

  if (allowedRoles && roleKey) {
    const role = String(localStorage.getItem(roleKey) || '').toLowerCase();
    const ok = allowedRoles.map((r) => String(r).toLowerCase()).includes(role);
    if (!ok) return <Navigate to={redirectTo} replace state={redirectState} />;
  }

  return <Outlet />;
}

export default ProtectedRoute;
