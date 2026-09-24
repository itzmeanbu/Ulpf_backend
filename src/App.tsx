import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import Sidebar from './components/layout/Sidebar';
import Header from './components/layout/Header';
import Dashboard from './pages/Dashboard';
import Logs from './pages/Logs';
import Admin from './pages/Admin';
import Settings from './pages/Settings';
import RecycleBin from './pages/RecycleBin';
import Login from './pages/Login';
import Register from './pages/Register';
import './pages/pages.css';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function AppLayout() {
  const { isAdmin } = useAuth();
  return (
    <div className="app-layout">
      <Sidebar />
      <div className="app-main">
        <Header />
        <div className="app-content">
          {isAdmin ? (
            // The admin only ever sees the Admin page (which has its own
            // Recycle Bin tab covering every category).
            <Routes>
              <Route path="/admin" element={<Admin />} />
              <Route path="*" element={<Navigate to="/admin" replace />} />
            </Routes>
          ) : (
            <Routes>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/logs" element={<Logs />} />
              <Route path="/recycle-bin" element={<RecycleBin />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Routes>
          )}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/*" element={<ProtectedRoute><AppLayout /></ProtectedRoute>} />
    </Routes>
  );
}
