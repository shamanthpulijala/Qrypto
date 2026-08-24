// ============================================================
// QuantumGuard AI — Auth Store (v2)
//
// Dual-mode auth:
//   - If VITE_API_URL is set → real JWT auth via backend
//   - Otherwise → client-only demo mode (original behaviour)
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
  loginError: string | null;
  isLoading: boolean;

  login: (email: string, password: string) => Promise<boolean>;
  logout: () => void;
  openLoginModal: () => void;
  closeLoginModal: () => void;
}

// ── Demo users (client-only fallback) ────────────────────────
const DEMO_USERS: Record<string, { password: string; profile: UserProfile }> = {
  'admin@quantumguard.ai': {
    password: 'quantum2024',
    profile: {
      name: 'Alex Rivera', email: 'admin@quantumguard.ai', role: 'Security Lead',
      initials: 'AR', avatarColor: 'linear-gradient(135deg, #00d4ff, #8b5cf6)',
    },
  },
  'security@example.com': {
    password: 'password123',
    profile: {
      name: 'Sam Chen', email: 'security@example.com', role: 'Security Analyst',
      initials: 'SC', avatarColor: 'linear-gradient(135deg, #22c55e, #14b8a6)',
    },
  },
  'ciso@example.com': {
    password: 'password123',
    profile: {
      name: 'Jordan Kim', email: 'ciso@example.com', role: 'CISO',
      initials: 'JK', avatarColor: 'linear-gradient(135deg, #f97316, #ef4444)',
    },
  },
};

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

// ── Store ─────────────────────────────────────────────────────
export const useAuthStore = create<AuthState>((set) => ({
  user: loadUser(),
  showLoginModal: false,
  loginError: null,
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

    // Demo fallback mode
    const match = DEMO_USERS[email.toLowerCase()];
    if (match && match.password === password) {
      localStorage.setItem('qg_user', JSON.stringify(match.profile));
      set({ user: match.profile, showLoginModal: false, loginError: null, isLoading: false });
      return true;
    }
    set({ loginError: 'Invalid email or password.', isLoading: false });
    return false;
  },

  logout: () => {
    setToken(null);
    localStorage.removeItem('qg_user');
    set({ user: null, loginError: null });
  },

  openLoginModal: () => set({ showLoginModal: true, loginError: null }),
  closeLoginModal: () => set({ showLoginModal: false, loginError: null }),
}));
