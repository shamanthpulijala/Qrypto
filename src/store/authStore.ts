// ============================================================
// Qrypto AI Advisor — Auth Store (v3)
//
// Dual-mode auth:
//   - If VITE_API_URL is set → real JWT auth via backend
//   - Otherwise → local-mode: users stored in localStorage
//                  passwords hashed with a simple digest
// ============================================================

import { create } from 'zustand';
import { authApi, setToken, isApiConfigured, type AuthUser } from '../api/client';

export interface UserProfile {
  id?: string;
  name: string;
  email: string;
  role: string;
  initials: string;
  avatarColor: string;
}

interface AuthState {
  user: UserProfile | null;
  showLoginModal: boolean;
  authMode: 'login' | 'register';
  loginError: string | null;
  registerError: string | null;
  isLoading: boolean;

  login: (email: string, password: string) => Promise<boolean>;
  register: (name: string, email: string, password: string) => Promise<boolean>;
  logout: () => void;
  openLoginModal: (mode?: 'login' | 'register') => void;
  closeLoginModal: () => void;
  setAuthMode: (mode: 'login' | 'register') => void;
}

// ── Local user store helpers ───────────────────────────────────
interface LocalUser {
  id: string;
  name: string;
  email: string;
  role: string;
  passwordHash: string;
}

function getLocalUsers(): LocalUser[] {
  try {
    const raw = localStorage.getItem('qg_local_users');
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

function saveLocalUsers(users: LocalUser[]): void {
  localStorage.setItem('qg_local_users', JSON.stringify(users));
}

// Simple deterministic hash for local-mode password storage.
// NOT cryptographically secure — purely for local browser-only demo use.
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode('qrypto_salt_' + password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Session helpers ───────────────────────────────────────────
function loadUser(): UserProfile | null {
  try {
    const raw = localStorage.getItem('qg_user');
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

function roleToAvatarColor(role: string): string {
  const palette: Record<string, string> = {
    ADMIN: 'linear-gradient(135deg, #00d4ff, #8b5cf6)',
    ANALYST: 'linear-gradient(135deg, #22c55e, #14b8a6)',
    EXECUTIVE: 'linear-gradient(135deg, #f97316, #ef4444)',
    DEVELOPER: 'linear-gradient(135deg, #3b82f6, #6366f1)',
    USER: 'linear-gradient(135deg, #00d4ff, #0066ff)',
  };
  return palette[role] ?? 'linear-gradient(135deg, #64748b, #475569)';
}

function apiUserToProfile(apiUser: AuthUser): UserProfile {
  return {
    id: apiUser.id,
    name: apiUser.name,
    email: apiUser.email,
    role: apiUser.role,
    initials: apiUser.name.split(' ').map(p => p[0]).join('').toUpperCase().slice(0, 2),
    avatarColor: roleToAvatarColor(apiUser.role),
  };
}

function localUserToProfile(u: LocalUser): UserProfile {
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
    initials: u.name.split(' ').map(p => p[0]).join('').toUpperCase().slice(0, 2),
    avatarColor: roleToAvatarColor(u.role),
  };
}

// ── Store ─────────────────────────────────────────────────────
export const useAuthStore = create<AuthState>((set) => ({
  user: loadUser(),
  showLoginModal: false,
  authMode: 'login',
  loginError: null,
  registerError: null,
  isLoading: false,

  login: async (email: string, password: string): Promise<boolean> => {
    set({ isLoading: true, loginError: null });

    // Real backend mode
    if (isApiConfigured()) {
      try {
        const { token, user: apiUser } = await authApi.login(email, password);
        setToken(token);
        const profile = apiUserToProfile(apiUser);
        localStorage.setItem('qg_user', JSON.stringify(profile));
        set({ user: profile, showLoginModal: false, loginError: null, isLoading: false });
        return true;
      } catch (err: any) {
        set({ loginError: err.message || 'Login failed', isLoading: false });
        return false;
      }
    }

    // Local-mode: verify against localStorage users
    try {
      const users = getLocalUsers();
      const passwordHash = await hashPassword(password);
      const match = users.find(u => u.email.toLowerCase() === email.toLowerCase() && u.passwordHash === passwordHash);

      if (!match) {
        set({ loginError: 'Incorrect email or password.', isLoading: false });
        return false;
      }

      const profile = localUserToProfile(match);
      localStorage.setItem('qg_user', JSON.stringify(profile));
      set({ user: profile, showLoginModal: false, loginError: null, isLoading: false });
      return true;
    } catch {
      set({ loginError: 'An unexpected error occurred. Please try again.', isLoading: false });
      return false;
    }
  },

  register: async (name: string, email: string, password: string): Promise<boolean> => {
    set({ isLoading: true, registerError: null });

    // Real backend mode
    if (isApiConfigured()) {
      try {
        const { token, user: apiUser } = await authApi.register(email, password, name, 'USER');
        setToken(token);
        const profile = apiUserToProfile(apiUser);
        localStorage.setItem('qg_user', JSON.stringify(profile));
        set({ user: profile, showLoginModal: false, registerError: null, isLoading: false });
        return true;
      } catch (err: any) {
        set({ registerError: err.message || 'Registration failed', isLoading: false });
        return false;
      }
    }

    // Local-mode: save new user to localStorage
    try {
      const users = getLocalUsers();
      const existing = users.find(u => u.email.toLowerCase() === email.toLowerCase());
      if (existing) {
        set({ registerError: 'An account with this email already exists.', isLoading: false });
        return false;
      }

      const passwordHash = await hashPassword(password);
      const newUser: LocalUser = {
        id: `local_${Date.now()}`,
        name: name.trim(),
        email: email.toLowerCase().trim(),
        role: 'USER',
        passwordHash,
      };

      saveLocalUsers([...users, newUser]);
      const profile = localUserToProfile(newUser);
      localStorage.setItem('qg_user', JSON.stringify(profile));
      set({ user: profile, showLoginModal: false, registerError: null, isLoading: false });
      return true;
    } catch {
      set({ registerError: 'An unexpected error occurred. Please try again.', isLoading: false });
      return false;
    }
  },

  logout: () => {
    setToken(null);
    localStorage.removeItem('qg_user');
    set({ user: null, loginError: null, registerError: null });
  },

  openLoginModal: (mode = 'login') => set({ showLoginModal: true, loginError: null, registerError: null, authMode: mode }),
  closeLoginModal: () => set({ showLoginModal: false, loginError: null, registerError: null }),
  setAuthMode: (mode) => set({ authMode: mode, loginError: null, registerError: null }),
}));
