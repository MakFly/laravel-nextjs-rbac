// ============================================================================
// User & Auth Types
// ============================================================================

export interface User {
  id: number;
  name: string;
  email: string;
  email_verified_at: string | null;
  avatar_url?: string;
  created_at: string;
  updated_at: string;
  roles: Role[];
  permissions: Permission[];
}

export interface AuthTokens {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token?: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  name: string;
  email: string;
  password: string;
  password_confirmation: string;
}

// ============================================================================
// RBAC Types
// ============================================================================

export interface Role {
  id: number;
  name: string;
  slug: string;
  description?: string;
  permissions?: Permission[];
  created_at: string;
  updated_at: string;
}

export interface Permission {
  id: number;
  name: string;
  slug: string;
  resource: string;
  action: PermissionAction;
  created_at: string;
  updated_at: string;
}

export type PermissionAction =
  | "create"
  | "read"
  | "update"
  | "delete"
  | "manage";

export type RoleSlug = "admin" | "moderator" | "user";

// ============================================================================
// API Response Types
// ============================================================================

export interface ApiResponse<T> {
  data: T;
  message?: string;
}

export interface ApiError {
  message: string;
  errors?: Record<string, string[]>;
}

export interface PaginatedResponse<T> {
  data: T[];
  meta: {
    current_page: number;
    last_page: number;
    per_page: number;
    total: number;
  };
  links: {
    first: string;
    last: string;
    prev: string | null;
    next: string | null;
  };
}

// ============================================================================
// OAuth Types
// ============================================================================

export type OAuthProvider = "google" | "github";

export interface OAuthRedirectResponse {
  url: string;
}

// ============================================================================
// Permission Check Helpers
// ============================================================================

export function hasPermission(
  user: User,
  resource: string,
  action: PermissionAction
): boolean {
  return user.permissions.some(
    (p) => p.resource === resource && (p.action === action || p.action === "manage")
  );
}

export function hasRole(user: User, roleSlug: RoleSlug): boolean {
  return user.roles.some((r) => r.slug === roleSlug);
}

export function isAdmin(user: User): boolean {
  return hasRole(user, "admin");
}
