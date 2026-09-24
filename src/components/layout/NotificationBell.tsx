import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, X } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import adminService from '../../services/adminService';
import logService from '../../services/logService';

// Notifications are derived from the existing access_requests endpoints:
//  - admin: GET /access-requests, filtered to status = 'pending'
//  - user:  GET /access-requests/mine, filtered to approved/rejected
// Users dismiss seen items; dismissed ids are remembered per user in the browser.

interface Notif {
  id: string;
  status: 'pending' | 'approved' | 'rejected';
  text: string;
  time: string;
}

const POLL_MS = 30000;
const typeLabel = (t?: string) => (t === 'upload' ? 'upload' : 'sensitive data');

function timeAgo(iso?: string) {
  if (!iso) return '';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}

export default function NotificationBell() {
  const { user, isAdmin } = useAuth() as any;
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<Notif[]>([]);
  const wrapRef = useRef<HTMLDivElement>(null);

  const storageKey = `ulpf_dismissed_notifs_${user?.id || user?.email || 'anon'}`;
  const getDismissed = useCallback((): string[] => {
    try { return JSON.parse(localStorage.getItem(storageKey) || '[]'); } catch { return []; }
  }, [storageKey]);

  const load = useCallback(async () => {
    if (!user) return;
    try {
      if (isAdmin) {
        const list: any[] = (await adminService.getAccessRequests()) as any;
        setItems(
          (list || [])
            .filter((r) => r.status === 'pending')
            .map((r) => ({
              id: r.id,
              status: 'pending',
              text: `${r.email} requested ${typeLabel(r.type)} access`,
              time: r.created_at,
            }))
        );
      } else {
        const list: any[] = (await logService.getMyAccessRequests()) as any;
        const dismissed = getDismissed();
        setItems(
          (list || [])
            .filter((r) => (r.status === 'approved' || r.status === 'rejected') && !dismissed.includes(r.id))
            .map((r) => ({
              id: r.id,
              status: r.status,
              text: `Your ${typeLabel(r.type)} access request was ${r.status}`,
              time: r.resolved_at || r.created_at,
            }))
        );
      }
    } catch {
      /* keep previous items; server may be waking up */
    }
  }, [user, isAdmin, getDismissed]);

  useEffect(() => {
    load();
    const t = setInterval(load, POLL_MS);
    const onFocus = () => load();
    window.addEventListener('focus', onFocus);
    return () => { clearInterval(t); window.removeEventListener('focus', onFocus); };
  }, [load]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const dismiss = (ids: string[]) => {
    const next = Array.from(new Set([...getDismissed(), ...ids])).slice(-200);
    localStorage.setItem(storageKey, JSON.stringify(next));
    setItems((cur) => cur.filter((n) => !ids.includes(n.id)));
  };

  const onClickItem = (n: Notif) => {
    if (isAdmin) {
      setOpen(false);
      navigate('/admin?tab=' + encodeURIComponent('Access requests'));
    } else {
      dismiss([n.id]);
    }
  };

  const count = items.length;

  return (
    <div className="notif-wrap" ref={wrapRef}>
      <button
        className="header-icon-btn"
        title="Notifications"
        onClick={() => { setOpen((o) => !o); if (!open) load(); }}
      >
        <Bell size={20} />
        {count > 0 && <span className="notif-count">{count > 9 ? '9+' : count}</span>}
      </button>

      {open && (
        <div className="notif-panel">
          <div className="notif-head">
            <span>Notifications</span>
            {!isAdmin && count > 0 && (
              <button onClick={() => dismiss(items.map((n) => n.id))}>Dismiss all</button>
            )}
            {isAdmin && count > 0 && (
              <button onClick={() => onClickItem(items[0])}>Review all</button>
            )}
          </div>
          {count === 0 ? (
            <div className="notif-empty">
              {isAdmin ? 'No pending access requests.' : 'You are all caught up.'}
            </div>
          ) : (
            items.map((n) => (
              <div key={n.id} className="notif-item" onClick={() => onClickItem(n)}>
                <span className={`notif-dot ${n.status}`} />
                <div className="notif-body">
                  <div className="notif-text">{n.text}</div>
                  <div className="notif-time">{timeAgo(n.time)}</div>
                </div>
                {!isAdmin && (
                  <button
                    className="notif-x"
                    title="Dismiss"
                    onClick={(e) => { e.stopPropagation(); dismiss([n.id]); }}
                  >
                    <X size={14} />
                  </button>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
