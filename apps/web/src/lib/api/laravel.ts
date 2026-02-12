/**
 * Server-side helper for Laravel Sanctum SPA requests
 *
 * All server-side requests to Laravel must forward cookies manually
 * because credentials: 'include' does NOT work in Node.js.
 */

'use server';

import { cookies } from 'next/headers';

const LARAVEL_API_URL = process.env.LARAVEL_API_URL || 'http://localhost:8000';
const APP_URL = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3001';

/**
 * Makes an authenticated request to Laravel SPA API
 *
 * - Forwards all browser cookies to Laravel
 * - Forwards XSRF-TOKEN as X-XSRF-TOKEN header
 * - Sets Referer header for Sanctum stateful domain check
 * - Forwards Set-Cookie headers back to the browser
 */
export async function laravelRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${LARAVEL_API_URL}/api/spa${endpoint}`;
  const cookieStore = await cookies();

  // Build cookie string from all cookies
  const allCookies = cookieStore.getAll();
  const cookieHeader = allCookies.map((c) => `${c.name}=${c.value}`).join('; ');

  // Get XSRF token for CSRF protection
  const xsrfToken = cookieStore.get('XSRF-TOKEN')?.value;

  const headers: Record<string, string> = {
    'Accept': 'application/json',
    'Referer': APP_URL,
    'Origin': APP_URL,
    ...(options.headers as Record<string, string>),
  };

  if (cookieHeader) {
    headers['Cookie'] = cookieHeader;
  }
  if (xsrfToken) {
    headers['X-XSRF-TOKEN'] = decodeURIComponent(xsrfToken);
  }

  // Set Content-Type for JSON body
  if (options.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  // Forward Set-Cookie headers from Laravel to the browser
  const setCookieHeaders = response.headers.getSetCookie();
  for (const setCookie of setCookieHeaders) {
    const [cookiePart] = setCookie.split(';');
    const eqIndex = cookiePart.indexOf('=');
    if (eqIndex === -1) continue;
    const name = cookiePart.substring(0, eqIndex).trim();
    const value = cookiePart.substring(eqIndex + 1);

    // Parse cookie attributes
    const isHttpOnly = setCookie.toLowerCase().includes('httponly');
    const isSecure = setCookie.toLowerCase().includes('secure');
    const pathMatch = setCookie.match(/path=([^;]+)/i);
    const maxAgeMatch = setCookie.match(/max-age=([^;]+)/i);

    cookieStore.set({
      name,
      value,
      httpOnly: isHttpOnly,
      secure: isSecure,
      sameSite: 'lax',
      path: pathMatch ? pathMatch[1].trim() : '/',
      ...(maxAgeMatch ? { maxAge: parseInt(maxAgeMatch[1].trim()) } : {}),
    });
  }

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

    const error = new Error(errorMessage) as Error & { statusCode: number; details: unknown };
    error.statusCode = response.status;
    error.details = errorDetails;
    throw error;
  }

  return response.json();
}

/**
 * Initialize CSRF cookie from Laravel
 *
 * Must be called before any POST/PUT/DELETE request to get the XSRF-TOKEN.
 */
export async function initCsrfServer(): Promise<void> {
  const url = `${LARAVEL_API_URL}/sanctum/csrf-cookie`;
  const cookieStore = await cookies();

  const allCookies = cookieStore.getAll();
  const cookieHeader = allCookies.map((c) => `${c.name}=${c.value}`).join('; ');

  const headers: Record<string, string> = {
    'Accept': 'application/json',
    'Referer': APP_URL,
    'Origin': APP_URL,
  };

  if (cookieHeader) {
    headers['Cookie'] = cookieHeader;
  }

  const response = await fetch(url, { headers });

  // Forward Set-Cookie headers (XSRF-TOKEN + laravel_session)
  const setCookieHeaders = response.headers.getSetCookie();
  for (const setCookie of setCookieHeaders) {
    const [cookiePart] = setCookie.split(';');
    const eqIndex = cookiePart.indexOf('=');
    if (eqIndex === -1) continue;
    const name = cookiePart.substring(0, eqIndex).trim();
    const value = cookiePart.substring(eqIndex + 1);

    const isHttpOnly = setCookie.toLowerCase().includes('httponly');
    const isSecure = setCookie.toLowerCase().includes('secure');
    const pathMatch = setCookie.match(/path=([^;]+)/i);

    cookieStore.set({
      name,
      value,
      httpOnly: isHttpOnly,
      secure: isSecure,
      sameSite: 'lax',
      path: pathMatch ? pathMatch[1].trim() : '/',
    });
  }
}
