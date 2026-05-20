// chronos-ai-guard/src/contexts/AuthContext.tsx
import React, { createContext, useContext, useState, useEffect } from "react";
import { AUTH_API_URL, apiFetch, clearSession } from "@/lib/apiClient";

export type UserRole = "admin" | "analyst" | "viewer";

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
}

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string, role: UserRole) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const initializeAuth = async () => {
      const token = localStorage.getItem("access_token");
      const storedUser = localStorage.getItem("aifim_user");
      if (token && storedUser) {
        try {
          const resp = await apiFetch(`${AUTH_API_URL}/auth/me`);
          if (resp.ok) {
            const fresh = (await resp.json()) as User;
            setUser(fresh);
            localStorage.setItem("aifim_user", JSON.stringify(fresh));
          } else {
            clearSession();
            setUser(null);
          }
        } catch {
          clearSession();
          setUser(null);
        }
      }
      setIsLoading(false);
    };
    initializeAuth();
  }, []);

  const login = async (email: string, password: string): Promise<void> => {
    const resp = await fetch(`${AUTH_API_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.error ?? `login failed: ${resp.status}`);
    }
    const data = await resp.json();
    localStorage.setItem("access_token", data.access_token);
    localStorage.setItem("aifim_user", JSON.stringify(data.user));
    setUser(data.user as User);
  };

  const register = async (
    username: string, email: string, password: string, role: UserRole,
  ): Promise<void> => {
    const resp = await fetch(`${AUTH_API_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email, password, role }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.error ?? `register failed: ${resp.status}`);
    }
    // v1: register does NOT auto-login. Caller redirects to /auth.
  };

  const logout = (): void => {
    clearSession();
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{ user, login, register, logout, isAuthenticated: !!user, isLoading }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const ctx = useContext(AuthContext);
  if (ctx === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
};
