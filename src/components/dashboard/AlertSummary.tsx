import React from 'react';
import { AlertTriangle, AlertCircle, Info } from 'lucide-react';

export default function AlertSummary({ summary }: { summary: any }) {
  if (!summary) return null;

  const alertTypes = [
    { label: 'Critical', count: summary.critical, dotClass: 'critical', icon: AlertCircle, color: 'var(--color-danger)' },
    { label: 'Warning', count: summary.warning, dotClass: 'warning', icon: AlertTriangle, color: 'var(--color-warning)' },
    { label: 'Info', count: summary.info, dotClass: 'info', icon: Info, color: 'var(--color-info)' },
  ];

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Alert Summary</h2>
        <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>
          {summary.active} active
        </span>
      </div>
      <div className="panel-body">
        <div className="alert-list">
          {alertTypes.map((type) => (
            <div key={type.label} className="alert-item">
              <div className="alert-item-left">
                <span className={`alert-dot ${type.dotClass}`}></span>
                <type.icon size={18} style={{ color: type.color }} />
                <span style={{ fontWeight: 500 }}>{type.label}</span>
              </div>
              <span className="alert-count">{type.count}</span>
            </div>
          ))}
        </div>

        {summary.recentAlerts && summary.recentAlerts.length > 0 && (
          <div style={{ marginTop: '16px', borderTop: '1px solid var(--color-border)', paddingTop: '16px' }}>
            <h3 style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: '12px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Latest Alerts
            </h3>
            {summary.recentAlerts.slice(0, 3).map((alert: any) => (
              <div
                key={alert.id}
                style={{ padding: '8px 0', borderBottom: '1px solid var(--color-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
              >
                <span style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>{alert.title}</span>
                <span className={`badge badge-${alert.severity}`}>{alert.severity}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
