'use client';

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

interface User {
  id: string;
  username: string;
  email: string;
  is_active: boolean;
  is_admin: boolean;
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  refreshToken: () => Promise<boolean>;
  getAccessToken: () => string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const ACCESS_TOKEN_KEY = 'quick_hack_access_token';
const REFRESH_TOKEN_KEY = 'quick_hack_refresh_token';

type FastAPIValidationErrorDetail = {
  loc?: Array<string | number>;
  msg?: string;
  type?: string;
};

type FastAPIErrorResponse = {
  detail?: string | FastAPIValidationErrorDetail[];
};

async function getErrorMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as FastAPIErrorResponse;
    const { detail } = body;

    if (typeof detail === 'string' && detail.trim()) {
      return detail;
    }

    if (Array.isArray(detail)) {
      const messages = detail
        .map((item) => {
          const loc = Array.isArray(item.loc)
            ? item.loc.filter((p) => p !== 'body').join('.')
            : '';
          const msg = item.msg || 'Invalid value';
          return loc ? `${loc}: ${msg}` : msg;
        })
        .filter(Boolean);

      if (messages.length > 0) {
        return messages.join('\n');
      }
    }
  } catch {
    // ignore
  }

  return response.statusText || 'Request failed';
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const getAccessToken = useCallback(() => {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem(ACCESS_TOKEN_KEY);
  }, []);

  const setTokens = useCallback((access: string, refresh: string) => {
    localStorage.setItem(ACCESS_TOKEN_KEY, access);
    localStorage.setItem(REFRESH_TOKEN_KEY, refresh);
  }, []);

  const clearTokens = useCallback(() => {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  }, []);

  const fetchUser = useCallback(async (token: string): Promise<User | null> => {
    try {
      const response = await fetch(`${API_BASE}/api/auth/me`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      console.error('Failed to fetch user:', error);
    }
    return null;
  }, []);

  const refreshToken = useCallback(async (): Promise<boolean> => {
    const refresh = localStorage.getItem(REFRESH_TOKEN_KEY);
    if (!refresh) return false;

    try {
      const response = await fetch(`${API_BASE}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refresh })
      });

      if (response.ok) {
        const data = await response.json();
        setTokens(data.access_token, data.refresh_token);
        const user = await fetchUser(data.access_token);
        setUser(user);
        return true;
      }
    } catch (error) {
      console.error('Failed to refresh token:', error);
    }

    clearTokens();
    setUser(null);
    return false;
  }, [setTokens, clearTokens, fetchUser]);

  const login = useCallback(async (username: string, password: string) => {
    const response = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (!response.ok) {
      throw new Error(await getErrorMessage(response));
    }

    const data = await response.json();
    setTokens(data.access_token, data.refresh_token);
    const user = await fetchUser(data.access_token);
    setUser(user);
  }, [setTokens, fetchUser]);

  const register = useCallback(async (username: string, email: string, password: string) => {
    const response = await fetch(`${API_BASE}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password })
    });

    if (!response.ok) {
      throw new Error(await getErrorMessage(response));
    }

    const data = await response.json();
    setTokens(data.access_token, data.refresh_token);
    const user = await fetchUser(data.access_token);
    setUser(user);
  }, [setTokens, fetchUser]);

  const logout = useCallback(() => {
    clearTokens();
    setUser(null);
  }, [clearTokens]);

  // Initialize auth state on mount
  useEffect(() => {
    const initAuth = async () => {
      const token = getAccessToken();
      if (token) {
        const user = await fetchUser(token);
        if (user) {
          setUser(user);
        } else {
          // Token might be expired, try refresh
          await refreshToken();
        }
      }
      setIsLoading(false);
    };

    initAuth();
  }, [getAccessToken, fetchUser, refreshToken]);

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        refreshToken,
        getAccessToken
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
