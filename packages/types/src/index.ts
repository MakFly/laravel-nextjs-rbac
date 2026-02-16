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
  is_impersonating?: boolean;
  impersonator?: { id: number; name: string; email: string } | null;
  onboarding_status: "pending" | "in_progress" | "completed";
  onboarding_step: number;
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
  action: PermissionAction,
): boolean {
  return (
    user.permissions?.some(
      (p) =>
        p.resource === resource &&
        (p.action === action || p.action === "manage"),
    ) ?? false
  );
}

export function hasRole(user: User, roleSlug: RoleSlug): boolean {
  return user.roles?.some((r) => r.slug === roleSlug) ?? false;
}

export function isAdmin(user: User): boolean {
  return hasRole(user, "admin");
}

// ============================================================================
// Onboarding Types
// ============================================================================

export interface PersonalInfoData {
  phone: string;
  date_of_birth: string;
  street: string;
  city: string;
  postal_code: string;
  country: string;
  nationality: string;
}

export interface IdentityVerificationData {
  id_document_type: "passport" | "national_id" | "drivers_license";
  id_document_number: string;
  id_expiry_date: string;
}

export interface FinancialProfileData {
  employment_status: string;
  annual_income_range: string;
  source_of_funds: string;
  investment_experience: string;
}

export interface OperationSetupData {
  account_type: "banking" | "crypto" | "both";
  preferred_currency?: string;
  iban?: string;
  preferred_cryptocurrency?: string;
  wallet_address?: string;
  initial_transaction_amount:
    | "under_1k"
    | "1k_10k"
    | "10k_50k"
    | "50k_100k"
    | "over_100k";
}

export interface OnboardingDraft {
  current_step: number;
  data: {
    step1?: PersonalInfoData;
    step2?: IdentityVerificationData;
    step3?: FinancialProfileData;
    step4?: OperationSetupData;
  };
  updated_at: string;
}
