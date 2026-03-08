import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';

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

function ProtectedRoute({
  redirectTo = '/login',
  tokenKey = 'token',
  roleKey = 'role',
  allowedRoles = null,
}) {
  const token = localStorage.getItem(tokenKey);
  if (!token) return <Navigate to={redirectTo} replace />;

  const payload = parseJwtPayload(token);
  if (!payload?.exp || payload.exp * 1000 <= Date.now()) {
    localStorage.removeItem(tokenKey);
    return <Navigate to={redirectTo} replace />;
  }

  if (allowedRoles && roleKey) {
    const role = String(localStorage.getItem(roleKey) || '').toLowerCase();
    const ok = allowedRoles.map((r) => String(r).toLowerCase()).includes(role);
    if (!ok) return <Navigate to={redirectTo} replace />;
  }

  return <Outlet />;
}

export default ProtectedRoute;
