// Mock log data
const LOG_SOURCES = ['Web Server', 'API Gateway', 'Database', 'Auth Service', 'Firewall', 'Load Balancer', 'DNS Server', 'Mail Server'];
const SEVERITIES = ['critical', 'warning', 'info', 'success'];

const LOG_MESSAGES = {
  critical: [
    'Database connection pool exhausted — max connections reached',
    'Disk usage exceeded 95% on primary storage',
    'SSL certificate expired for api.ulpf.com',
    'Memory allocation failure in auth microservice',
    'Unhandled exception in payment processing module',
  ],
  warning: [
    'High CPU usage detected: 87% for last 5 minutes',
    'Response time degradation: avg 2.3s (threshold: 1s)',
    'Rate limiting triggered for IP 192.168.1.105',
    'Failed login attempts: 15 in the last hour from single IP',
    'Backup job completed with warnings — 3 files skipped',
  ],
  info: [
    'Deployment completed successfully: v2.4.1',
    'Scheduled maintenance window started',
    'New user registration: john.doe@example.com',
    'Cache cleared and rebuilt: 1,234 entries',
    'Health check passed for all 12 services',
  ],
  success: [
    'Auto-scaling triggered: 3 → 5 instances',
    'Database migration completed successfully',
    'Backup completed: 2.4 GB compressed',
    'Security scan completed: no vulnerabilities found',
    'Certificate renewed for api.ulpf.com',
  ],
};

function generateLogs(count = 50) {
  const logs = [];
  const now = Date.now();

  for (let i = 0; i < count; i++) {
    const severity = SEVERITIES[Math.floor(Math.random() * SEVERITIES.length)];
    const messages = LOG_MESSAGES[severity];
    logs.push({
      id: `log-${String(i + 1).padStart(4, '0')}`,
      timestamp: new Date(now - Math.random() * 86400000 * 7).toISOString(),
      severity,
      source: LOG_SOURCES[Math.floor(Math.random() * LOG_SOURCES.length)],
      message: messages[Math.floor(Math.random() * messages.length)],
      ipAddress: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    });
  }

  return logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

const MOCK_LOGS = generateLogs(50);

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const logMock = {
  async getLogs(filters = {}) {
    await delay(600);
    let logs = [...MOCK_LOGS];
    if (filters.severity) {
      logs = logs.filter((l) => l.severity === filters.severity);
    }
    if (filters.source) {
      logs = logs.filter((l) => l.source === filters.source);
    }
    return { logs, total: logs.length };
  },

  async getLogById(id) {
    await delay(300);
    const log = MOCK_LOGS.find((l) => l.id === id);
    if (!log) throw new Error('Log not found');
    return log;
  },

  async getLogStats() {
    await delay(500);
    const stats = {
      total: MOCK_LOGS.length,
      critical: MOCK_LOGS.filter((l) => l.severity === 'critical').length,
      warning: MOCK_LOGS.filter((l) => l.severity === 'warning').length,
      info: MOCK_LOGS.filter((l) => l.severity === 'info').length,
      success: MOCK_LOGS.filter((l) => l.severity === 'success').length,
      sources: LOG_SOURCES.map((source) => ({
        name: source,
        count: MOCK_LOGS.filter((l) => l.source === source).length,
      })),
      recentEvents: MOCK_LOGS.slice(0, 10),
    };
    return stats;
  },
};
