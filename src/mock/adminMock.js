// Mock admin data
const MOCK_USERS_LIST = [
  { id: '1', name: 'Admin User', email: 'admin@ulpf.com', role: 'admin', status: 'active', lastLogin: new Date(Date.now() - 300000).toISOString() },
  { id: '2', name: 'John Doe', email: 'john@ulpf.com', role: 'user', status: 'active', lastLogin: new Date(Date.now() - 3600000).toISOString() },
  { id: '3', name: 'Jane Smith', email: 'jane@ulpf.com', role: 'user', status: 'active', lastLogin: new Date(Date.now() - 7200000).toISOString() },
  { id: '4', name: 'Bob Wilson', email: 'bob@ulpf.com', role: 'viewer', status: 'inactive', lastLogin: new Date(Date.now() - 604800000).toISOString() },
  { id: '5', name: 'Alice Brown', email: 'alice@ulpf.com', role: 'user', status: 'active', lastLogin: new Date(Date.now() - 86400000).toISOString() },
];

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const adminMock = {
  async getUsers() {
    await delay(600);
    return { users: MOCK_USERS_LIST, total: MOCK_USERS_LIST.length };
  },

  async updateUserRole(userId, newRole) {
    await delay(400);
    const user = MOCK_USERS_LIST.find((u) => u.id === userId);
    if (!user) throw new Error('User not found');
    user.role = newRole;
    return user;
  },

  async getSystemStats() {
    await delay(500);
    return {
      uptime: '99.97%',
      totalRequests: 1248567,
      avgResponseTime: '142ms',
      activeConnections: 342,
      cpuUsage: 45,
      memoryUsage: 67,
      diskUsage: 54,
      services: [
        { name: 'Web Server', status: 'healthy', uptime: '99.99%' },
        { name: 'API Gateway', status: 'healthy', uptime: '99.98%' },
        { name: 'Database', status: 'degraded', uptime: '99.85%' },
        { name: 'Auth Service', status: 'healthy', uptime: '99.99%' },
        { name: 'Cache', status: 'healthy', uptime: '100%' },
      ],
    };
  },
};
