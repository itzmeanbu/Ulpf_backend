import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, FileText, Shield, Settings, Trash2 } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

// Alerts management lives only inside the Admin page (Admin > Alerts tab) -
// everyone else just sees the Alert Summary on their Dashboard.
const navItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/logs', icon: FileText, label: 'Logs' },
  { to: '/recycle-bin', icon: Trash2, label: 'Recycle Bin' },
  { to: '/admin', icon: Shield, label: 'Admin', adminOnly: true },
];

export default function Sidebar() {
  const { isAdmin, canUpload } = useAuth();
  // Admin sees ONLY the Admin page (which has its own Recycle Bin tab).
  // Everyone else sees everything except Admin.
  // Viewers are read-only, so they have nothing to restore: no Recycle Bin for them.
  const items = navItems
    .filter((i) => (isAdmin ? i.adminOnly : !i.adminOnly))
    .filter((i) => i.to !== '/recycle-bin' || canUpload);

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <Shield size={28} />
        <h2>ULPF</h2>
      </div>

      <nav className="sidebar-nav">
        {items.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <item.icon size={20} />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      {!isAdmin && (
      <div className="sidebar-footer">
        <NavLink
          to="/settings"
          className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
        >
          <Settings size={20} />
          <span>Settings</span>
        </NavLink>
      </div>
      )}
    </aside>
  );
}
