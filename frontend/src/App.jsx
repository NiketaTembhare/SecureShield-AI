import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Login from './pages/Login.jsx';
import Signup from './pages/Signup.jsx';
import Chat from './pages/Chat.jsx';
import Dashboard from './pages/Dashboard.jsx';
import { getToken, isTokenValid, getUserRole } from './lib/api.js';

function PrivateRoute({ children }) {
  const token = getToken();
  if (!token || !isTokenValid(token)) return <Navigate to="/login" replace />;
  return children;
}

function AdminRoute({ children }) {
  const token = getToken();
  if (!token || !isTokenValid(token)) return <Navigate to="/login" replace />;
  if (getUserRole(token) !== 'admin') return <Navigate to="/chat" replace />;
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/chat" replace />} />
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />
      <Route path="/chat" element={<PrivateRoute><Chat /></PrivateRoute>} />
      <Route path="/dashboard" element={<AdminRoute><Dashboard /></AdminRoute>} />
      <Route path="*" element={<Navigate to="/chat" replace />} />
    </Routes>
  );
}
