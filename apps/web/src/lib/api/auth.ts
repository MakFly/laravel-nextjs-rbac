/**
 * Server Actions for authentication
 *
 * These actions use the BFF to communicate with Laravel.
 * Authentication now uses HttpOnly cookies.
 */

'use server';

import { cookies } from 'next/headers';
import type { User, LoginCredentials, RegisterData, AuthTokens, ApiResponse } from '@rbac/types';

/**
 * Base URL of Next.js BFF
 */
const BFF_URL = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

/**
 * Custom BFF error
 */
class BffRequestError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public details?: unknown
  ) {
    super(message);
    this.name = 'BffRequestError';
  }
}

/**
 * Makes a request to the BFF
 */
async function bffRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<ApiResponse<T>> {
  const url = `${BFF_URL}${endpoint}`;

  // Get cookie for authenticated requests
  const cookieStore = await cookies();
  const authToken = cookieStore.get('auth_token');

  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...options.headers,
  };

  // For server-to-server requests, must pass cookie manually
  // because credentials: 'include' only works on browser side
  if (authToken?.value) {
    (headers as Record<string, string>)['Cookie'] = `auth_token=${authToken.value}`;
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorMessage = 'Request failed';
    let errorDetails: unknown = undefined;

    try {
      const errorData = await response.json();
      errorMessage = errorData.message || errorData.error || errorMessage;
      errorDetails = errorData;
    } catch {
      errorMessage = `HTTP ${response.status}: ${response.statusText}`;
    }

    throw new BffRequestError(errorMessage, response.status, errorDetails);
  }

  const data = await response.json();

  // Handle return cookies (new token, etc.)
  const setCookieHeaders = response.headers.getSetCookie();
  setCookieHeaders.forEach((cookieHeader) => {
    const [cookiePart] = cookieHeader.split(';');
    const [name, value] = cookiePart.split('=');
    if (name && value) {
      cookieStore.set({
        name,
        value,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 60 * 60 * 24 * 15, // 15 days
      });
    }
  });

  return data;
}

/**
 * Register a new user
 */
export async function registerAction(
  data: RegisterData
): Promise<ApiResponse<{ user: User; access_token: string }>> {
  return bffRequest<{ user: User; access_token: string }>('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

/**
 * Log in a user
 */
export async function loginAction(
  credentials: LoginCredentials
): Promise<ApiResponse<{ user: User; access_token: string }>> {
  return bffRequest<{ user: User; access_token: string }>('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  });
}

/**
 * Log out
 */
export async function logoutAction(): Promise<void> {
  try {
    await bffRequest('/api/v1/auth/logout', {
      method: 'POST',
    });
  } finally {
    // Delete cookie on client side
    const cookieStore = await cookies();
    cookieStore.delete('auth_token');
  }
}

/**
 * Refresh token
 */
export async function refreshTokenAction(): Promise<ApiResponse<AuthTokens>> {
  return bffRequest<AuthTokens>('/api/v1/auth/refresh', {
    method: 'POST',
  });
}

/**
 * Get current user
 *
 * Note: Returns null if user is not logged in
 * (rather than throwing an error)
 */
export async function getCurrentUserAction(): Promise<User | null> {
  try {
    const response = await bffRequest<User>('/api/v1/me');
    return response.data;
  } catch (error) {
    // If user is not logged in (401) or BFF rejects (403),
    // return null silently
    if (error instanceof BffRequestError) {
      if (error.statusCode === 401 || error.statusCode === 403) {
        return null;
      }
    }
    throw error;
  }
}

/**
 * Get list of OAuth providers
 */
export async function getOAuthProvidersAction(): Promise<ApiResponse<string[]>> {
  return bffRequest<string[]>('/api/v1/auth/providers');
}

/**
 * Get OAuth redirect URL
 */
export async function getOAuthUrlAction(provider: string): Promise<{ url: string }> {
  const response = await bffRequest<{ redirect_url: string }>(
    `/api/v1/auth/${provider}/redirect`
  );

  return { url: response.data.redirect_url };
}
