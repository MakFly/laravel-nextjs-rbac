import { create } from 'zustand';
import type { User, PermissionAction, RoleSlug } from '@rbac/types';
import { hasPermission as checkHasPermission, hasRole as checkHasRole, isAdmin as checkIsAdmin } from '@rbac/types';
import {
  loginAction,
  registerAction,
  logoutAction,
  getCurrentUserAction,
} from '@/lib/api/auth';
import {
  impersonateUserAction,
  stopImpersonatingAction,
} from '@/lib/api/admin';
import type { LoginCredentials, RegisterData, OAuthProvider } from '@rbac/types';

const LARAVEL_API_URL = process.env.NEXT_PUBLIC_LARAVEL_API_URL || 'http://localhost:8000';

interface AuthState {
  user: User | null;
  isHydrated: boolean;
  isLoading: boolean;
  error: string | null;

  // Impersonation
  isImpersonating: boolean;
  impersonator: { id: number; name: string; email: string } | null;

  // Actions
  setUser: (user: User | null) => void;
  hydrate: (user: User | null) => void;
  login: (credentials: LoginCredentials) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  loginWithOAuth: (provider: OAuthProvider) => void;
  clearError: () => void;

  // Impersonation actions
  impersonate: (userId: number) => Promise<void>;
  stopImpersonating: () => Promise<void>;

  // Computed
  isAuthenticated: () => boolean;
  needsOnboarding: () => boolean;
  hasPermission: (resource: string, action: PermissionAction) => boolean;
  hasRole: (roleSlug: RoleSlug) => boolean;
  isAdmin: () => boolean;
}

function extractImpersonationState(user: User | null) {
  return {
    isImpersonating: user?.is_impersonating ?? false,
    impersonator: user?.impersonator ?? null,
  };
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  isHydrated: false,
  isLoading: false,
  error: null,
  isImpersonating: false,
  impersonator: null,

  setUser: (user) => set({ user, ...extractImpersonationState(user) }),

  hydrate: (user) => set({ user, isHydrated: true, ...extractImpersonationState(user) }),

  login: async (credentials) => {
    set({ error: null, isLoading: true });
    try {
      const response = await loginAction(credentials);
      const user = response.data.user;
      set({ user, isLoading: false, ...extractImpersonationState(user) });
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
      const user = response.data.user;
      set({ user, isLoading: false, ...extractImpersonationState(user) });
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
      set({ user: null, isLoading: false, isImpersonating: false, impersonator: null });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Logout failed';
      set({ error: message, user: null, isLoading: false, isImpersonating: false, impersonator: null });
    }
  },

  refreshUser: async () => {
    set({ error: null });
    try {
      const user = await getCurrentUserAction();
      set({ user, ...extractImpersonationState(user) });
    } catch (err) {
      set({ user: null, isImpersonating: false, impersonator: null });
      const message = err instanceof Error ? err.message : 'Failed to refresh user';
      set({ error: message });
      throw err;
    }
  },

  loginWithOAuth: (provider) => {
    window.location.href = `${LARAVEL_API_URL}/api/auth/${provider}/redirect?client=spa`;
  },

  clearError: () => set({ error: null }),

  // Impersonation
  impersonate: async (userId) => {
    set({ error: null, isLoading: true });
    try {
      const response = await impersonateUserAction(userId);
      const user = response.data;
      set({ user, isLoading: false, ...extractImpersonationState(user) });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Impersonation failed';
      set({ error: message, isLoading: false });
      throw err;
    }
  },

  stopImpersonating: async () => {
    set({ error: null, isLoading: true });
    try {
      const response = await stopImpersonatingAction();
      const user = response.data;
      set({ user, isLoading: false, ...extractImpersonationState(user) });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to stop impersonation';
      set({ error: message, isLoading: false });
      throw err;
    }
  },

  // Computed helpers
  isAuthenticated: () => !!get().user,

  needsOnboarding: () => get().user?.onboarding_status !== 'completed',

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
export const useIsImpersonating = () => useAuthStore((s) => s.isImpersonating);
