// ============================================================
// Qrypto AI Advisor — Auth Store (Firebase Edition)
// ============================================================

import { create } from 'zustand';
import { 
  signInWithEmailAndPassword, 
  createUserWithEmailAndPassword, 
  signOut, 
  onAuthStateChanged,
  updateProfile,
  type User as FirebaseUser
} from 'firebase/auth';
import { auth } from '../lib/firebase';

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
  isInitialized: boolean;

  initAuth: () => void;
  login: (email: string, password: string) => Promise<boolean>;
  register: (name: string, email: string, password: string) => Promise<boolean>;
  logout: () => void;
  openLoginModal: (mode?: 'login' | 'register') => void;
  closeLoginModal: () => void;
  setAuthMode: (mode: 'login' | 'register') => void;
}

// ── Session helpers ───────────────────────────────────────────

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

function firebaseUserToProfile(apiUser: FirebaseUser): UserProfile {
  const name = apiUser.displayName || apiUser.email?.split('@')[0] || 'Unknown User';
  return {
    id: apiUser.uid,
    name,
    email: apiUser.email || '',
    role: 'USER', // Defaulting to USER, in a real app this might come from custom claims
    initials: name.split(' ').map(p => p[0]).join('').toUpperCase().slice(0, 2),
    avatarColor: roleToAvatarColor('USER'),
  };
}

// ── Store ─────────────────────────────────────────────────────
export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  showLoginModal: false,
  authMode: 'login',
  loginError: null,
  registerError: null,
  isLoading: false,
  isInitialized: false,

  initAuth: () => {
    onAuthStateChanged(auth, (firebaseUser) => {
      if (firebaseUser) {
        set({ user: firebaseUserToProfile(firebaseUser), isInitialized: true });
      } else {
        set({ user: null, isInitialized: true });
      }
    });
  },

  login: async (email: string, password: string): Promise<boolean> => {
    set({ isLoading: true, loginError: null });
    try {
      await signInWithEmailAndPassword(auth, email, password);
      set({ showLoginModal: false, loginError: null, isLoading: false });
      return true;
    } catch (err: any) {
      set({ loginError: err.message || 'Incorrect email or password.', isLoading: false });
      return false;
    }
  },

  register: async (name: string, email: string, password: string): Promise<boolean> => {
    set({ isLoading: true, registerError: null });
    try {
      const userCredential = await createUserWithEmailAndPassword(auth, email, password);
      
      // Update Firebase profile with the provided name
      await updateProfile(userCredential.user, {
        displayName: name.trim()
      });
      
      // Force update of local state immediately since onAuthStateChanged might not catch the profile update
      set({ 
        user: firebaseUserToProfile({ ...userCredential.user, displayName: name.trim() } as FirebaseUser),
        showLoginModal: false, 
        registerError: null, 
        isLoading: false 
      });
      
      return true;
    } catch (err: any) {
      set({ registerError: err.message || 'An unexpected error occurred.', isLoading: false });
      return false;
    }
  },

  logout: async () => {
    try {
      await signOut(auth);
      set({ user: null, loginError: null, registerError: null });
    } catch (err) {
      console.error("Logout failed", err);
    }
  },

  openLoginModal: (mode = 'login') => set({ showLoginModal: true, loginError: null, registerError: null, authMode: mode }),
  closeLoginModal: () => set({ showLoginModal: false, loginError: null, registerError: null }),
  setAuthMode: (mode) => set({ authMode: mode, loginError: null, registerError: null }),
}));
