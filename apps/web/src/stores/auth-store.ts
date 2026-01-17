import { create } from 'zustand';
import type { User, PermissionAction, RoleSlug } from '@rbac/types';
import { hasPermission as checkHasPermission, hasRole as checkHasRole, isAdmin as checkIsAdmin } from '@rbac/types';
import {
  loginAction,
  registerAction,
  logoutAction,
  getCurrentUserAction,
  getOAuthUrlAction,
} from '@/lib/api/auth';
import type { LoginCredentials, RegisterData, OAuthProvider } from '@rbac/types';

interface AuthState {
  user: User | null;
  isHydrated: boolean;
  isLoading: boolean;
  error: string | null;

  // Actions
  setUser: (user: User | null) => void;
  hydrate: (user: User | null) => void;
  login: (credentials: LoginCredentials) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  loginWithOAuth: (provider: OAuthProvider) => Promise<void>;
  clearError: () => void;

  // Computed
  isAuthenticated: () => boolean;
  hasPermission: (resource: string, action: PermissionAction) => boolean;
  hasRole: (roleSlug: RoleSlug) => boolean;
  isAdmin: () => boolean;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  isHydrated: false,
  isLoading: false,
  error: null,

  setUser: (user) => set({ user }),

  hydrate: (user) => set({ user, isHydrated: true }),

  login: async (credentials) => {
    set({ error: null, isLoading: true });
    try {
      const response = await loginAction(credentials);
      set({ user: response.data.user, isLoading: false });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Login failed';
      set({ error: message, isLoading: false });
      throw err;
    }
  },

  register: async (data) => {
    set({ error: null, isLoading: true });
    try {
      const response = await registerAction(data);
      set({ user: response.data.user, isLoading: false });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Registration failed';
      set({ error: message, isLoading: false });
      throw err;
    }
  },

  logout: async () => {
    set({ error: null, isLoading: true });
    try {
      await logoutAction();
      set({ user: null, isLoading: false });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Logout failed';
      set({ error: message, user: null, isLoading: false });
    }
  },

  refreshUser: async () => {
    set({ error: null });
    try {
      const user = await getCurrentUserAction();
      set({ user });
    } catch (err) {
      set({ user: null });
      const message = err instanceof Error ? err.message : 'Failed to refresh user';
      set({ error: message });
      throw err;
    }
  },

  loginWithOAuth: async (provider) => {
    try {
      const { url } = await getOAuthUrlAction(provider);
      window.location.href = url;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'OAuth redirect failed';
      set({ error: message });
      throw err;
    }
  },

  clearError: () => set({ error: null }),

  // Computed helpers
  isAuthenticated: () => !!get().user,

  hasPermission: (resource, action) => {
    const { user } = get();
    if (!user) return false;
    return checkHasPermission(user, resource, action);
  },

  hasRole: (roleSlug) => {
    const { user } = get();
    if (!user) return false;
    return checkHasRole(user, roleSlug);
  },

  isAdmin: () => {
    const { user } = get();
    if (!user) return false;
    return checkIsAdmin(user);
  },
}));

// Selector hooks for convenience
export const useUser = () => useAuthStore((s) => s.user);
export const useIsHydrated = () => useAuthStore((s) => s.isHydrated);
export const useIsAuthenticated = () => useAuthStore((s) => !!s.user);
