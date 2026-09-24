import api from './api';

const alertService = {
  getAlerts() {
    return api.get('/alerts');
  },
  getAlertSummary() {
    return api.get('/alerts/summary');
  },
  // Admin only. status: open | investigating | resolved
  updateAlertStatus(id: string, status: string) {
    return api.post(`/admin/alerts/${id}/status`, { status });
  },
  // Admin only - moves an alert into the Recycle Bin.
  deleteAlert(id: string) {
    return api.delete(`/admin/alerts/${id}`);
  },
};

export default alertService;
