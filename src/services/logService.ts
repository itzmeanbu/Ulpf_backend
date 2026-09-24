import api from './api';

const logService = {
  getLogStats() {
    return api.get('/logs/stats');
  },
  // Backend search is GET /logs/search?query=...&scope=mine|all
  //   'mine' = only logs I uploaded, 'all' = every log
  searchLogs(query = '', scope: 'mine' | 'all' = 'all') {
    return api.get('/logs/search', { params: { query, scope } });
  },
  getLogById(id: string) {
    return api.get(`/logs/${id}`);
  },
  uploadLog(rawLog: string, sourceType?: string) {
    const body: Record<string, string> = { rawLog };
    if (sourceType) body.sourceType = sourceType;
    return api.post('/logs/upload', body);
  },
  unlockLog(id: string, secondaryPassword: string) {
    return api.post(`/logs/${id}/unlock`, { secondaryPassword });
  },
  requestSensitiveAccess() {
    return api.post('/access-requests', { type: 'sensitive' });
  },
  // A viewer asks an admin for permission to upload logs (approval = analyst).
  requestUploadAccess() {
    return api.post('/access-requests', { type: 'upload' });
  },
  getMyAccessRequests() {
    return api.get('/access-requests/mine');
  },

  /* --- Delete / select all / clear all --- */
  deleteLog(id: string) {
    return api.delete(`/logs/${id}`);
  },
  bulkDeleteLogs(ids: string[]) {
    return api.post('/logs/bulk-delete', { ids });
  },
  clearAllLogs() {
    return api.post('/logs/clear-all');
  },

  /* --- Recycle Bin (logs) --- */
  getRecycleBin() {
    return api.get('/logs/recycle-bin');
  },
  restoreLog(id: string) {
    return api.post(`/logs/recycle-bin/${id}/restore`);
  },
  restoreLogsBulk(ids: string[]) {
    return api.post('/logs/recycle-bin/restore-bulk', { ids });
  },
  permanentlyDeleteLog(id: string) {
    return api.delete(`/logs/recycle-bin/${id}`);
  },
  permanentlyDeleteLogsBulk(ids: string[]) {
    return api.post('/logs/recycle-bin/permanent-delete-bulk', { ids });
  },
  emptyRecycleBin() {
    return api.post('/logs/recycle-bin/empty');
  },
};

export default logService;
