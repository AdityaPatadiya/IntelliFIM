import React, { createContext, useContext, useState, useEffect } from 'react';

export type UserRole = 'admin' | 'analyst' | 'viewer';

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

// Update this to your actual API URL
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const initializeAuth = async () => {
      const token = localStorage.getItem('access_token');
      const storedUser = localStorage.getItem('aifim_user');

      if (token && storedUser) {
        try {
          // Validate token by fetching user data
          await fetchCurrentUser(token);
          setUser(JSON.parse(storedUser));
        } catch (error) {
          // Token invalid or expired, clear storage
          localStorage.removeItem('access_token');
          localStorage.removeItem('aifim_user');
          setUser(null);
        }
      }
      setIsLoading(false);
    };

    initializeAuth();
  }, []);

  const fetchCurrentUser = async (token: string) => {
    const response = await fetch(`${API_BASE_URL}/api/auth/me/`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user');
    }

    const data = await response.json();
    return data;
  };

  const login = async (email: string, password: string) => {
    const response = await fetch(`${API_BASE_URL}/api/auth/login/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Login failed');
    }

    const data = await response.json();
    console.log('🔍 Login response:', data); // Debug log

    const { access_token, user: userData } = data;

    if (!access_token) {
      throw new Error('No access token received');
    }

    // Store token
    localStorage.setItem('access_token', access_token);

    const user: User = {
      id: userData.id.toString(),
      username: userData.username,
      email: userData.email,
      role: userData.is_admin ? 'admin' : 'viewer', // Adjust based on your role system
    };

    setUser(user);
    localStorage.setItem('aifim_user', JSON.stringify(user));
  };

  const register = async (username: string, email: string, password: string, role: UserRole = 'viewer') => {
    const response = await fetch(`${API_BASE_URL}/api/auth/register/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username,
        email,
        password,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Registration failed');
    }

    const data = await response.json();
    console.log('🔍 Register response:', data); // Debug log

    const { access_token, user: userData } = data;

    // Store token and user
    localStorage.setItem('access_token', access_token);

    const user: User = {
      id: userData.id.toString(),
      username: userData.username,
      email: userData.email,
      role: userData.is_admin ? 'admin' : 'viewer',
    };

    setUser(user);
    localStorage.setItem('aifim_user', JSON.stringify(user));

    if (userData.is_admin) {
      console.log('Welcome, Administrator!');
    }
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('aifim_user');
    localStorage.removeItem('access_token');
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        register,
        logout,
        isAuthenticated: !!user,
        isLoading,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
