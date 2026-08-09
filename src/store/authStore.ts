// ============================================================
// QuantumGuard AI — Auth Store
// Simple client-side login with user profile
// ============================================================

import { create } from 'zustand';

export interface UserProfile {
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

  login: (email: string, password: string) => boolean;
  logout: () => void;
  openLoginModal: () => void;
  closeLoginModal: () => void;
}

// Predefined demo users (no real backend needed)
const DEMO_USERS: Record<string, { password: string; profile: UserProfile }> = {
  'admin@quantumguard.ai': {
    password: 'quantum2024',
    profile: { name: 'Alex Rivera', email: 'admin@quantumguard.ai', role: 'Security Lead', initials: 'AR', avatarColor: 'linear-gradient(135deg, #00d4ff, #8b5cf6)' },
  },
  'security@example.com': {
    password: 'password123',
    profile: { name: 'Sam Chen', email: 'security@example.com', role: 'Security Analyst', initials: 'SC', avatarColor: 'linear-gradient(135deg, #22c55e, #14b8a6)' },
  },
  'ciso@example.com': {
    password: 'password123',
    profile: { name: 'Jordan Kim', email: 'ciso@example.com', role: 'CISO', initials: 'JK', avatarColor: 'linear-gradient(135deg, #f97316, #ef4444)' },
  },
};

// Persist user session in localStorage
function loadUser(): UserProfile | null {
  try {
    const raw = localStorage.getItem('qg_user');
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

export const useAuthStore = create<AuthState>((set) => ({
  user: loadUser(),
  showLoginModal: false,
  loginError: null,

  login: (email, password) => {
    const match = DEMO_USERS[email.toLowerCase()];
    if (match && match.password === password) {
      localStorage.setItem('qg_user', JSON.stringify(match.profile));
      set({ user: match.profile, showLoginModal: false, loginError: null });
      return true;
    }
    set({ loginError: 'Invalid email or password.' });
    return false;
  },

  logout: () => {
    localStorage.removeItem('qg_user');
    set({ user: null, loginError: null });
  },

  openLoginModal: () => set({ showLoginModal: true, loginError: null }),
  closeLoginModal: () => set({ showLoginModal: false, loginError: null }),
}));
