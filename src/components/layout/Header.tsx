import React from 'react';
import { useAuth } from '../../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { LogOut } from 'lucide-react';
import NotificationBell from './NotificationBell';

export default function Header() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const getInitials = (name?: string | null) => {
    if (!name) return '?';
    return name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  return (
    <header className="header">
      <div className="header-left">
        <h1>Unified Log Processing Framework</h1>
      </div>

      <div className="header-right">
        <NotificationBell />

        <div className="user-menu">
          <div className="user-avatar">{getInitials(user?.email)}</div>
          <div className="user-info">
            <span className="user-name">{user?.email || 'User'}</span>
            <span className="user-role">{user?.role || 'user'}</span>
          </div>
        </div>

        <button className="header-icon-btn" onClick={handleLogout} title="Logout">
          <LogOut size={20} />
        </button>
      </div>
    </header>
  );
}
