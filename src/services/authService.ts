import api, { USE_MOCK } from './api';
import { authMock } from '../mock/authMock';

const authService = {
  async login(email: string, password: string) {
    if (USE_MOCK) return authMock.login(email, password);
    return api.post('/auth/login', { email, password });
  },

  async register(name: string, email: string, password: string) {
    if (USE_MOCK) return authMock.register(name, email, password);
    return api.post('/auth/register', { name, email, password });
  },

  async getCurrentUser() {
    if (USE_MOCK) {
      const token = localStorage.getItem('ulpf_token');
      return authMock.getCurrentUser(token);
    }
    return api.get('/auth/me');
  },

  logout() {
    localStorage.removeItem('ulpf_token');
    localStorage.removeItem('ulpf_user');
  },
};

export default authService;
