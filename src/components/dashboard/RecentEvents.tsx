import React from 'react';

function formatTime(iso?: string | null): string {
  if (!iso) return '-';
  const date = new Date(iso);
  if (isNaN(date.getTime())) return '-';
  const diff = Date.now() - date.getTime();
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  return date.toLocaleDateString();
}

export default function RecentEvents({ events = [] }: { events?: any[] }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Recent Events</h2>
        {events.length > 0 && (
          <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>
            Last {events.length} events
          </span>
        )}
      </div>
      <div className="panel-body" style={{ padding: events.length ? 0 : undefined }}>
        {events.length === 0 ? (
          <p style={{ color: 'var(--color-text-muted)', textAlign: 'center', padding: '20px' }}>
            No recent events. Upload a log on the Logs page.
          </p>
        ) : (
          <table className="events-table">
            <thead>
              <tr><th>Vendor</th><th>Event</th><th>Action</th><th>Time</th></tr>
            </thead>
            <tbody>
              {events.map((e, i) => (
                <tr key={e.eventId || i}>
                  <td>{e.vendor || '-'}</td>
                  <td>{e.eventType || '-'}</td>
                  <td><span className="badge badge-info">{e.action || 'n/a'}</span></td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatTime(e.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
