/**
 * Server Actions for authentication (Sanctum SPA mode)
 *
 * Uses Laravel Sanctum session-based auth via server-side helper.
 * No more Passport tokens or HMAC.
 */

'use server';

import type { User, LoginCredentials, RegisterData, ApiResponse } from '@rbac/types';
import { laravelRequest, initCsrfServer } from './laravel';

/**
 * Register a new user
 */
export async function registerAction(
  data: RegisterData
): Promise<ApiResponse<{ user: User }>> {
  await initCsrfServer();
  return laravelRequest<ApiResponse<{ user: User }>>('/auth/register', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

/**
 * Log in a user
 */
export async function loginAction(
  credentials: LoginCredentials
): Promise<ApiResponse<{ user: User }>> {
  await initCsrfServer();
  return laravelRequest<ApiResponse<{ user: User }>>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  });
}

/**
 * Log out
 */
export async function logoutAction(): Promise<void> {
  await laravelRequest('/auth/logout', { method: 'POST' });
}

/**
 * Get current user
 *
 * Returns null if user is not logged in.
 */
export async function getCurrentUserAction(): Promise<User | null> {
  try {
    const response = await laravelRequest<{ data: User }>('/me');
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
export async function getOAuthProvidersAction(): Promise<ApiResponse<string[]>> {
  return laravelRequest<ApiResponse<string[]>>('/auth/providers');
}
