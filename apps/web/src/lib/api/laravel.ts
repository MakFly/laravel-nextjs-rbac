/**
 * Server-side helper for Laravel API requests
 *
 * Supports two authentication methods:
 * 1. Sanctum SPA (session-based) - /api/spa/*
 * 2. Passport (token-based with cookies) - /api/v1/*
 *
 * All server-side requests to Laravel must forward cookies manually
 * because credentials: 'include' does NOT work in Node.js.
 */

"use server";

import { cookies } from "next/headers";

const LARAVEL_API_URL = process.env.LARAVEL_API_URL || "http://localhost:8000";
const APP_URL = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3001";

const ACCESS_TOKEN_COOKIE = "access_token";
const REFRESH_TOKEN_COOKIE = "refresh_token";

/**
 * Set token cookies from response
 */
function setTokenCookies(
  cookieStore: ReturnType<typeof cookies>,
  setCookieHeaders: string[],
): void {
  for (const setCookie of setCookieHeaders) {
    const [cookiePart] = setCookie.split(";");
    const eqIndex = cookiePart.indexOf("=");
    if (eqIndex === -1) continue;
    const name = cookiePart.substring(0, eqIndex).trim();
    const value = cookiePart.substring(eqIndex + 1);

    const isHttpOnly = setCookie.toLowerCase().includes("httponly");
    const isSecure = setCookie.toLowerCase().includes("secure");
    const pathMatch = setCookie.match(/path=([^;]+)/i);
    const maxAgeMatch = setCookie.match(/max-age=([^;]+)/i);

    cookieStore.set({
      name,
      value,
      httpOnly: isHttpOnly,
      secure: isSecure,
      sameSite: "lax",
      path: pathMatch ? pathMatch[1].trim() : "/",
      ...(maxAgeMatch ? { maxAge: parseInt(maxAgeMatch[1].trim()) } : {}),
    });
  }
}

/**
 * Makes an authenticated request to Laravel SPA API (Sanctum session-based)
 *
 * - Uses /api/spa/* endpoints
 * - Forwards all browser cookies to Laravel
 * - Forwards XSRF-TOKEN as X-XSRF-TOKEN header
 * - Sets Referer header for Sanctum stateful domain check
 * - Forwards Set-Cookie headers back to the browser
 */
export async function laravelRequest<T>(
  endpoint: string,
  options: RequestInit = {},
): Promise<T> {
  const url = `${LARAVEL_API_URL}/api/spa${endpoint}`;
  const cookieStore = await cookies();

  const allCookies = cookieStore.getAll();
  const cookieHeader = allCookies.map((c) => `${c.name}=${c.value}`).join("; ");

  const xsrfToken = cookieStore.get("XSRF-TOKEN")?.value;

  const headers: Record<string, string> = {
    Accept: "application/json",
    Referer: APP_URL,
    Origin: APP_URL,
    ...(options.headers as Record<string, string>),
  };

  if (cookieHeader) {
    headers["Cookie"] = cookieHeader;
  }
  if (xsrfToken) {
    headers["X-XSRF-TOKEN"] = decodeURIComponent(xsrfToken);
  }

  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  const setCookieHeaders = response.headers.getSetCookie();
  setTokenCookies(cookieStore, setCookieHeaders);

  if (!response.ok) {
    let errorMessage = "Request failed";
    let errorDetails: unknown = undefined;

    try {
      const errorData = await response.json();
      errorMessage = errorData.message || errorData.error || errorMessage;
      errorDetails = errorData;
    } catch {
      errorMessage = `HTTP ${response.status}: ${response.statusText}`;
    }

    const error = new Error(errorMessage) as Error & {
      statusCode: number;
      details: unknown;
    };
    error.statusCode = response.status;
    error.details = errorDetails;
    throw error;
  }

  return response.json();
}

/**
 * Makes an authenticated request to Laravel Token API (Passport token-based)
 *
 * - Uses /api/v1/* endpoints
 * - Uses Bearer token from cookie for authentication
 * - Automatically refreshes token on 401
 * - Forwards Set-Cookie headers back to the browser
 */
export async function tokenRequest<T>(
  endpoint: string,
  options: RequestInit = {},
  retry = true,
): Promise<T> {
  const url = `${LARAVEL_API_URL}/api/v1${endpoint}`;
  const cookieStore = await cookies();

  const accessToken = cookieStore.get(ACCESS_TOKEN_COOKIE)?.value;

  const headers: Record<string, string> = {
    Accept: "application/json",
    Referer: APP_URL,
    Origin: APP_URL,
    ...(options.headers as Record<string, string>),
  };

  if (accessToken) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }

  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  const setCookieHeaders = response.headers.getSetCookie();
  setTokenCookies(cookieStore, setCookieHeaders);

  if (response.status === 401 && retry) {
    const refreshed = await refreshToken();
    if (refreshed) {
      return tokenRequest<T>(endpoint, options, false);
    }
  }

  if (!response.ok) {
    let errorMessage = "Request failed";
    let errorDetails: unknown = undefined;

    try {
      const errorData = await response.json();
      errorMessage = errorData.message || errorData.error || errorMessage;
      errorDetails = errorData;
    } catch {
      errorMessage = `HTTP ${response.status}: ${response.statusText}`;
    }

    const error = new Error(errorMessage) as Error & {
      statusCode: number;
      details: unknown;
    };
    error.statusCode = response.status;
    error.details = errorDetails;
    throw error;
  }

  return response.json();
}

/**
 * Refresh the access token using the refresh token cookie
 */
export async function refreshToken(): Promise<boolean> {
  try {
    const url = `${LARAVEL_API_URL}/api/v1/auth/token/refresh`;
    const cookieStore = await cookies();
    const refreshToken = cookieStore.get(REFRESH_TOKEN_COOKIE)?.value;

    if (!refreshToken) {
      return false;
    }

    const headers: Record<string, string> = {
      Accept: "application/json",
      Referer: APP_URL,
      Origin: APP_URL,
    };

    const response = await fetch(url, {
      method: "POST",
      headers,
    });

    const setCookieHeaders = response.headers.getSetCookie();
    setTokenCookies(cookieStore, setCookieHeaders);

    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Login with token-based auth (returns tokens in cookies)
 */
export async function tokenLogin(credentials: {
  email: string;
  password: string;
}): Promise<{ user: unknown; access_token: string }> {
  const url = `${LARAVEL_API_URL}/api/v1/auth/token/login`;
  const cookieStore = await cookies();

  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
    Referer: APP_URL,
    Origin: APP_URL,
  };

  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(credentials),
  });

  const setCookieHeaders = response.headers.getSetCookie();
  setTokenCookies(cookieStore, setCookieHeaders);

  if (!response.ok) {
    let errorMessage = "Login failed";
    try {
      const errorData = await response.json();
      errorMessage = errorData.message || errorMessage;
    } catch {
      errorMessage = `HTTP ${response.status}: ${response.statusText}`;
    }
    throw new Error(errorMessage);
  }

  const data = await response.json();
  return { user: data.data.user, access_token: data.data.access_token };
}

/**
 * Logout with token-based auth (clears token cookies)
 */
export async function tokenLogout(): Promise<void> {
  try {
    await tokenRequest("/auth/token/logout", { method: "POST" });
  } finally {
    const cookieStore = await cookies();
    cookieStore.delete(ACCESS_TOKEN_COOKIE);
    cookieStore.delete(REFRESH_TOKEN_COOKIE);
  }
}

/**
 * Get current user using token-based auth
 */
export async function getCurrentUserToken(): Promise<unknown | null> {
  try {
    const response = await tokenRequest<{ data: unknown }>("/me");
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
 * Initialize CSRF cookie from Laravel (for Sanctum SPA)
 */
export async function initCsrfServer(): Promise<void> {
  const url = `${LARAVEL_API_URL}/sanctum/csrf-cookie`;
  const cookieStore = await cookies();

  const allCookies = cookieStore.getAll();
  const cookieHeader = allCookies.map((c) => `${c.name}=${c.value}`).join("; ");

  const headers: Record<string, string> = {
    Accept: "application/json",
    Referer: APP_URL,
    Origin: APP_URL,
  };

  if (cookieHeader) {
    headers["Cookie"] = cookieHeader;
  }

  const response = await fetch(url, { headers });

  const setCookieHeaders = response.headers.getSetCookie();
  setTokenCookies(cookieStore, setCookieHeaders);
}
