import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';

// Set to true to use mock data instead of the real backend
export const USE_MOCK = false;
const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://ulpf-95ou.onrender.com/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  // Render's free server can take ~50 seconds to wake up, so wait longer.
  timeout: 60000,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = localStorage.getItem('ulpf_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (response) => response.data,
  (error: AxiosError<{ error?: string }>) => {
    const url = error.config?.url || '';
    const isAuthForm = url.includes('/auth/login') || url.includes('/auth/register');

    if (error.response?.status === 401 && !isAuthForm) {
      localStorage.removeItem('ulpf_token');
      localStorage.removeItem('ulpf_user');
      window.location.href = '/login';
    }

    let message = error.response?.data?.error || error.message || 'Something went wrong';
    if (error.code === 'ECONNABORTED') {
      message = 'The server is waking up. Please wait a few seconds and try again.';
    } else if (!error.response) {
      message = 'Cannot reach the server. Check your internet, or wait a moment if it is waking up.';
    }
    return Promise.reject(new Error(message));
  }
);

export default api;
