/**
 * BFF Route Handler
 *
 * This catch-all handler proxies all /api/v1/* requests to Laravel
 * while automatically adding HMAC signature.
 */

import { type NextRequest, NextResponse } from 'next/server';
import { generateSignature, buildLaravelPath } from '@/lib/security/hmac';
import { BffException, BffErrorCode, type HmacHeaders } from '@/lib/security/types';
import { cookies } from 'next/headers';

/**
 * Laravel configuration
 */
const LARAVEL_API_URL = process.env.LARAVEL_API_URL || 'http://localhost:8000';
const BFF_TIMEOUT = 30000; // 30 seconds

/**
 * Type for Next.js 14+ dynamic route params
 */
interface RouteParams {
  params: Promise<{ path: string[] }>;
}

/**
 * Regex to validate path segments (alphanumerics, dashes, underscores only)
 */
const SAFE_PATH_SEGMENT = /^[a-zA-Z0-9_-]+$/;

/**
 * Validates path segments to prevent SSRF/Path Traversal attacks
 * @throws {BffException} if path contains dangerous segments
 */
function validatePathSegments(segments: string[]): void {
  for (const segment of segments) {
    // Reject empty segments
    if (!segment) {
      throw new BffException(BffErrorCode.INVALID_SIGNATURE, 'Invalid path: empty segment');
    }

    // Reject path traversal
    if (segment === '..' || segment === '.') {
      throw new BffException(BffErrorCode.INVALID_SIGNATURE, 'Invalid path: traversal not allowed');
    }

    // Reject absolute URLs
    if (segment.includes('://') || segment.startsWith('//')) {
      throw new BffException(BffErrorCode.INVALID_SIGNATURE, 'Invalid path: absolute URLs not allowed');
    }

    // Validate segment format (alphanumerics, dashes, underscores)
    if (!SAFE_PATH_SEGMENT.test(segment)) {
      throw new BffException(BffErrorCode.INVALID_SIGNATURE, 'Invalid path: forbidden characters');
    }
  }
}

/**
 * Main proxy function to Laravel
 */
async function proxyRequest(
  request: NextRequest,
  method: string,
  paramsPromise: RouteParams['params']
): Promise<NextResponse> {
  try {
    // Extract path from params
    const params = await paramsPromise;
    const pathSegments = params.path;

    // Validate segments to prevent SSRF
    validatePathSegments(pathSegments);

    const bffPath = `/api/v1/${pathSegments.join('/')}`;

    // Rebuild Laravel path (WITHOUT leading slash to match Laravel)
    const laravelPath = buildLaravelPath(bffPath).replace(/^\//, '');
    const laravelUrl = new URL(laravelPath, LARAVEL_API_URL);

    // Double check: ensure final URL points to Laravel
    const expectedHost = new URL(LARAVEL_API_URL).host;
    if (laravelUrl.host !== expectedHost) {
      throw new BffException(BffErrorCode.INVALID_SIGNATURE, 'Invalid request: host mismatch');
    }

    // Get body for signature
    const clonedRequest = request.clone();
    let body: unknown = null;

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      try {
        const contentType = request.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          body = await clonedRequest.json();
        }
      } catch {
        // No body or non-JSON
      }
    }

    // Generate HMAC signature with parsed body
    const hmacResult = generateSignature(method, laravelPath, body);
    const hmacHeaders: HmacHeaders = {
      'X-BFF-Id': hmacResult['X-BFF-Id'],
      'X-BFF-Timestamp': hmacResult['X-BFF-Timestamp'],
      'X-BFF-Signature': hmacResult['X-BFF-Signature'],
    };

    const cookieStore = await cookies();

    // Prepare headers for Laravel
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...hmacHeaders,
    };

    // Public routes that don't require authentication
    const publicRoutes = [
      'api/v1/auth/login',
      'api/v1/auth/register',
      'api/v1/auth/providers',
    ];
    const isPublicRoute = publicRoutes.some((route) => laravelPath.startsWith(route));

    // Transfer auth token if present (Bearer token for Laravel)
    const authToken = cookieStore.get('auth_token')?.value;

    if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    } else if (!isPublicRoute) {
      return NextResponse.json(
        { error: 'Unauthorized', message: 'No auth token found' },
        { status: 401 }
      );
    }

    // Create AbortController for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), BFF_TIMEOUT);

    try {
      // Prepare fetch options
      const options: RequestInit = {
        method,
        headers,
        signal: controller.signal,
      };

      // Send normalized (sorted) body to match signature
      if (hmacResult.normalizedBody !== undefined) {
        options.body = hmacResult.normalizedBody;
      }

      // Copy query params
      request.nextUrl.searchParams.forEach((value, key) => {
        laravelUrl.searchParams.set(key, value);
      });

      // Make request to Laravel
      const response = await fetch(laravelUrl.toString(), options);

      clearTimeout(timeoutId);

      // Get response cookies (new token, etc.)
      const setCookieHeaders = response.headers.getSetCookie();
      const responseHeaders = new Headers();

      // Copy important response headers
      response.headers.forEach((value, key) => {
        if (key !== 'set-cookie') {
          responseHeaders.set(key, value);
        }
      });

      // Transfer cookies from Laravel
      setCookieHeaders.forEach((cookie) => {
        responseHeaders.append('set-cookie', cookie);
      });

      // Get response body
      const responseData = await response.text();

      // Create Next.js response
      const nextResponse = new NextResponse(responseData, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });

      // If Laravel returns access_token, set HttpOnly cookie
      try {
        const jsonData = JSON.parse(responseData);
        if (jsonData.data?.access_token) {
          const token = jsonData.data.access_token;
          const expiresAt = new Date();
          expiresAt.setDate(expiresAt.getDate() + 15); // 15 days

          // Set HttpOnly cookie
          nextResponse.cookies.set('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/',
            expires: expiresAt,
          });
        }
      } catch {
        // No JSON or no token
      }

      return nextResponse;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error && error.name === 'AbortError') {
        throw new BffException(BffErrorCode.TIMEOUT, 'Request timeout');
      }

      throw error;
    }
  } catch (error) {
    // Error handling
    if (error instanceof BffException) {
      return NextResponse.json(
        { error: error.message, code: error.code },
        { status: 500 }
      );
    }

    return NextResponse.json(
      { error: 'Internal server error', message: 'Failed to proxy request' },
      { status: 500 }
    );
  }
}

/**
 * Handlers for each HTTP method
 */
export async function GET(request: NextRequest, params: RouteParams) {
  return proxyRequest(request, 'GET', params.params);
}

export async function POST(request: NextRequest, params: RouteParams) {
  return proxyRequest(request, 'POST', params.params);
}

export async function PUT(request: NextRequest, params: RouteParams) {
  return proxyRequest(request, 'PUT', params.params);
}

export async function PATCH(request: NextRequest, params: RouteParams) {
  return proxyRequest(request, 'PATCH', params.params);
}

export async function DELETE(request: NextRequest, params: RouteParams) {
  return proxyRequest(request, 'DELETE', params.params);
}

/**
 * Configure route options
 */
export const runtime = 'nodejs'; // Required for crypto
export const dynamic = 'force-dynamic'; // Disable cache for sensitive routes
