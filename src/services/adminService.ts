import api from './api';

const adminService = {
  getOverview: () => api.get('/admin/overview'),

  getUsers: () => api.get('/admin/users'),
  updateUserRole: (id: string, role: string) => api.post(`/admin/users/${id}/role`, { role }),
  disableUser: (id: string) => api.post(`/admin/users/${id}/disable`),
  enableUser: (id: string) => api.post(`/admin/users/${id}/enable`),
  deleteUser: (id: string) => api.delete(`/admin/users/${id}`),
  revokeSensitive: (id: string) => api.post(`/admin/users/${id}/revoke-sensitive`),

  getAccessRequests: () => api.get('/access-requests'),
  approveAccessRequest: (id: string) => api.post(`/access-requests/${id}/approve`),
  rejectAccessRequest: (id: string) => api.post(`/access-requests/${id}/reject`),

  getSources: () => api.get('/admin/sources'),
  addSource: (name: string, vendor?: string) => api.post('/admin/sources', { name, vendor }),
  updateSource: (id: string, data: Record<string, any>) => api.patch(`/admin/sources/${id}`, data),
  deleteSource: (id: string) => api.delete(`/admin/sources/${id}`),

  getLogAccess: () => api.get('/admin/log-access'),
  setLogAccess: (userId: string, categories: string[]) => api.post(`/admin/log-access/${userId}`, { categories }),

  getAudit: () => api.get('/admin/audit'),
  getReport: (type: string) => api.get(`/admin/reports/${type}`),
  getSecurityStatus: () => api.get('/admin/security-status'),

  getMasking: () => api.get('/admin/masking-config'),
  saveMasking: (cfg: Record<string, boolean>) => api.post('/admin/masking-config', cfg),
  getAiSettings: () => api.get('/admin/ai-settings'),
  saveAiSettings: (cfg: Record<string, any>) => api.post('/admin/ai-settings', cfg),
  getSystemSettings: () => api.get('/admin/system-settings'),
  saveSystemSettings: (cfg: Record<string, any>) => api.post('/admin/system-settings', cfg),
  setSecondaryPassword: (newPassword: string) => api.post('/admin/secondary-password', { newPassword }),

  /* --- Recycle Bin (accounts / alerts / sources) --- */
  getRecycleBinSummary: () => api.get('/admin/recycle-bin/summary'),

  getDeletedAccounts: () => api.get('/admin/recycle-bin/accounts'),
  restoreAccount: (id: string) => api.post(`/admin/recycle-bin/accounts/${id}/restore`),
  restoreAccountsBulk: (ids: string[]) => api.post('/admin/recycle-bin/accounts/restore-bulk', { ids }),
  permanentlyDeleteAccount: (id: string) => api.delete(`/admin/recycle-bin/accounts/${id}`),
  permanentlyDeleteAccountsBulk: (ids: string[]) => api.post('/admin/recycle-bin/accounts/permanent-delete-bulk', { ids }),
  emptyAccountsRecycleBin: () => api.post('/admin/recycle-bin/accounts/empty'),

  getDeletedAlerts: () => api.get('/admin/recycle-bin/alerts'),
  restoreAlert: (id: string) => api.post(`/admin/recycle-bin/alerts/${id}/restore`),
  restoreAlertsBulk: (ids: string[]) => api.post('/admin/recycle-bin/alerts/restore-bulk', { ids }),
  permanentlyDeleteAlert: (id: string) => api.delete(`/admin/recycle-bin/alerts/${id}`),
  permanentlyDeleteAlertsBulk: (ids: string[]) => api.post('/admin/recycle-bin/alerts/permanent-delete-bulk', { ids }),
  emptyAlertsRecycleBin: () => api.post('/admin/recycle-bin/alerts/empty'),

  getDeletedSources: () => api.get('/admin/recycle-bin/sources'),
  restoreSource: (id: string) => api.post(`/admin/recycle-bin/sources/${id}/restore`),
  restoreSourcesBulk: (ids: string[]) => api.post('/admin/recycle-bin/sources/restore-bulk', { ids }),
  permanentlyDeleteSource: (id: string) => api.delete(`/admin/recycle-bin/sources/${id}`),
  permanentlyDeleteSourcesBulk: (ids: string[]) => api.post('/admin/recycle-bin/sources/permanent-delete-bulk', { ids }),
  emptySourcesRecycleBin: () => api.post('/admin/recycle-bin/sources/empty'),

  emptyEntireRecycleBin: () => api.post('/admin/recycle-bin/empty-all'),
};

export default adminService;
