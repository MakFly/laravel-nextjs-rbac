/**
 * Server Actions for authentication
 *
 * Supports two authentication methods:
 * 1. Sanctum SPA mode (session-based) - default
 * 2. Passport token mode (cookie-based with refresh token)
 */

"use server";

import type {
  User,
  LoginCredentials,
  RegisterData,
  ApiResponse,
} from "@rbac/types";
import {
  laravelRequest,
  initCsrfServer,
  tokenLogin,
  tokenLogout,
  getCurrentUserToken,
  tokenRequest,
  refreshToken,
} from "./laravel";

/**
 * Register a new user (Sanctum SPA mode)
 */
export async function registerAction(
  data: RegisterData,
): Promise<ApiResponse<{ user: User }>> {
  await initCsrfServer();
  return laravelRequest<ApiResponse<{ user: User }>>("/auth/register", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

/**
 * Log in a user (Sanctum SPA mode)
 */
export async function loginAction(
  credentials: LoginCredentials,
): Promise<ApiResponse<{ user: User }>> {
  await initCsrfServer();
  return laravelRequest<ApiResponse<{ user: User }>>("/auth/login", {
    method: "POST",
    body: JSON.stringify(credentials),
  });
}

/**
 * Log out (Sanctum SPA mode)
 */
export async function logoutAction(): Promise<void> {
  await laravelRequest("/auth/logout", { method: "POST" });
}

/**
 * Get current user (Sanctum SPA mode)
 *
 * Returns null if user is not logged in.
 */
export async function getCurrentUserAction(): Promise<User | null> {
  try {
    const response = await laravelRequest<{ data: User }>("/me");
    return response.data;
  } catch (error) {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode === 401 || err.statusCode === 403) {
      return null;
    }
    throw error;
  }
}

/**
 * Get list of OAuth providers
 */
export async function getOAuthProvidersAction(): Promise<
  ApiResponse<string[]>
> {
  return laravelRequest<ApiResponse<string[]>>("/auth/providers");
}

// =========================================================================
// Token-based auth (Passport with cookies)
// =========================================================================

/**
 * Log in with token-based auth (Passport + cookies)
 */
export async function tokenLoginAction(
  credentials: LoginCredentials,
): Promise<ApiResponse<{ user: User; access_token: string }>> {
  const result = await tokenLogin(credentials);
  return {
    data: {
      user: result.user as User,
      access_token: result.access_token,
    },
    message: "Login successful",
  };
}

/**
 * Log out with token-based auth (clears cookies)
 */
export async function tokenLogoutAction(): Promise<void> {
  await tokenLogout();
}

/**
 * Get current user with token-based auth
 */
export async function getCurrentUserTokenAction(): Promise<User | null> {
  return getCurrentUserToken() as Promise<User | null>;
}

/**
 * Refresh the access token
 */
export async function refreshTokenAction(): Promise<boolean> {
  return refreshToken();
}

/**
 * Make an authenticated request with token-based auth
 */
export async function tokenApiRequest<T>(
  endpoint: string,
  options: RequestInit = {},
): Promise<T> {
  return tokenRequest<T>(endpoint, options);
}
