import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import authService from '../services/authService';

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: string;
  sensitiveAccess: boolean;
}

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<any>;
  register: (name: string, email: string, password: string) => Promise<any>;
  logout: () => void;
  refreshUser: () => Promise<AuthUser>;
  isAdmin: boolean;
  canUpload: boolean; // analyst or admin
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const shape = (data: any): AuthUser => ({
    id: data.id,
    email: data.email,
    name: data.email,
    role: data.role,
    sensitiveAccess: Boolean(data.sensitive_access ?? data.sensitiveAccess),
  });

  const refreshUser = useCallback(async () => {
    const data = await authService.getCurrentUser();
    const u = shape(data);
    setUser(u);
    return u;
  }, []);

  useEffect(() => {
    const token = localStorage.getItem('ulpf_token');
    if (!token) {
      setLoading(false);
      return;
    }
    refreshUser()
      .catch(() => {
        localStorage.removeItem('ulpf_token');
        localStorage.removeItem('ulpf_user');
      })
      .finally(() => setLoading(false));
  }, [refreshUser]);

  const login = async (email: string, password: string) => {
    const response = await authService.login(email, password);
    localStorage.setItem('ulpf_token', response.token);
    await refreshUser();
    return response;
  };

  const register = (name: string, email: string, password: string) => authService.register(name, email, password);

  const logout = () => {
    authService.logout();
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user, loading, login, register, logout, refreshUser,
        isAdmin: user?.role === 'admin',
        canUpload: user?.role === 'admin' || user?.role === 'analyst',
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
}
