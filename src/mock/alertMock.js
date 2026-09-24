// Mock alert data
const MOCK_ALERTS = [
  {
    id: 'alert-001',
    title: 'Critical: Database Connection Failure',
    message: 'Primary database server is not responding. Failover initiated to secondary.',
    severity: 'critical',
    status: 'active',
    source: 'Database',
    createdAt: new Date(Date.now() - 1800000).toISOString(),
    acknowledgedAt: null,
  },
  {
    id: 'alert-002',
    title: 'High Memory Usage on Web Server',
    message: 'Memory usage on web-server-03 has exceeded 90% for more than 10 minutes.',
    severity: 'warning',
    status: 'active',
    source: 'Web Server',
    createdAt: new Date(Date.now() - 3600000).toISOString(),
    acknowledgedAt: null,
  },
  {
    id: 'alert-003',
    title: 'Suspicious Login Activity Detected',
    message: '47 failed login attempts from IP 10.0.45.12 in the last 30 minutes.',
    severity: 'critical',
    status: 'active',
    source: 'Auth Service',
    createdAt: new Date(Date.now() - 7200000).toISOString(),
    acknowledgedAt: null,
  },
  {
    id: 'alert-004',
    title: 'SSL Certificate Expiring Soon',
    message: 'SSL certificate for dashboard.ulpf.com expires in 7 days.',
    severity: 'warning',
    status: 'acknowledged',
    source: 'Load Balancer',
    createdAt: new Date(Date.now() - 14400000).toISOString(),
    acknowledgedAt: new Date(Date.now() - 10000000).toISOString(),
  },
  {
    id: 'alert-005',
    title: 'Scheduled Backup Completed',
    message: 'Nightly backup completed successfully. 2.4 GB transferred.',
    severity: 'info',
    status: 'resolved',
    source: 'Database',
    createdAt: new Date(Date.now() - 28800000).toISOString(),
    acknowledgedAt: new Date(Date.now() - 25000000).toISOString(),
  },
  {
    id: 'alert-006',
    title: 'API Rate Limit Warning',
    message: 'API rate limit at 85% for tenant acme-corp. Consider upgrading plan.',
    severity: 'warning',
    status: 'active',
    source: 'API Gateway',
    createdAt: new Date(Date.now() - 5400000).toISOString(),
    acknowledgedAt: null,
  },
  {
    id: 'alert-007',
    title: 'New Firewall Rule Applied',
    message: 'Firewall rule FW-2024-089 has been applied to block traffic from malicious IPs.',
    severity: 'info',
    status: 'resolved',
    source: 'Firewall',
    createdAt: new Date(Date.now() - 43200000).toISOString(),
    acknowledgedAt: new Date(Date.now() - 40000000).toISOString(),
  },
  {
    id: 'alert-008',
    title: 'Disk Space Warning on Log Server',
    message: 'Log server disk usage at 88%. Old logs need to be archived or deleted.',
    severity: 'warning',
    status: 'active',
    source: 'Web Server',
    createdAt: new Date(Date.now() - 9000000).toISOString(),
    acknowledgedAt: null,
  },
];

let alerts = [...MOCK_ALERTS];

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const alertMock = {
  async getAlerts(filters = {}) {
    await delay(600);
    let result = [...alerts];
    if (filters.severity) {
      result = result.filter((a) => a.severity === filters.severity);
    }
    if (filters.status) {
      result = result.filter((a) => a.status === filters.status);
    }
    return { alerts: result, total: result.length };
  },

  async getAlertSummary() {
    await delay(400);
    const active = alerts.filter((a) => a.status === 'active');
    return {
      total: alerts.length,
      active: active.length,
      critical: active.filter((a) => a.severity === 'critical').length,
      warning: active.filter((a) => a.severity === 'warning').length,
      info: active.filter((a) => a.severity === 'info').length,
      recentAlerts: alerts.slice(0, 5),
    };
  },

  async acknowledgeAlert(id) {
    await delay(400);
    const alert = alerts.find((a) => a.id === id);
    if (!alert) throw new Error('Alert not found');
    alert.status = 'acknowledged';
    alert.acknowledgedAt = new Date().toISOString();
    return alert;
  },
};
