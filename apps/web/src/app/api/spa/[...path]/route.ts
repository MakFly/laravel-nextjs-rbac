/**
 * SPA Proxy Route Handler
 *
 * Proxies all /api/spa/* requests to Laravel while forwarding
 * cookies and CSRF tokens for Sanctum session-based auth.
 */

import { type NextRequest, NextResponse } from 'next/server';

const LARAVEL_API_URL = process.env.LARAVEL_API_URL || 'http://localhost:8000';
const PROXY_TIMEOUT = 30000;

interface RouteParams {
  params: Promise<{ path: string[] }>;
}

async function proxyRequest(
  request: NextRequest,
  method: string,
  paramsPromise: RouteParams['params']
): Promise<NextResponse> {
  try {
    const params = await paramsPromise;
    const pathSegments = params.path;
    const laravelPath = `/api/spa/${pathSegments.join('/')}`;
    const laravelUrl = new URL(laravelPath, LARAVEL_API_URL);

    // Copy query params
    request.nextUrl.searchParams.forEach((value, key) => {
      laravelUrl.searchParams.set(key, value);
    });

    // Forward browser cookies to Laravel
    const cookieHeader = request.headers.get('cookie') || '';
    const xsrfToken = request.headers.get('x-xsrf-token') || '';

    const headers: HeadersInit = {
      'Accept': 'application/json',
      'Referer': process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3001',
      'Origin': process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3001',
    };

    if (cookieHeader) {
      headers['Cookie'] = cookieHeader;
    }
    if (xsrfToken) {
      headers['X-XSRF-TOKEN'] = xsrfToken;
    }

    // Forward Content-Type if present
    const contentType = request.headers.get('content-type');
    if (contentType) {
      headers['Content-Type'] = contentType;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), PROXY_TIMEOUT);

    try {
      const options: RequestInit = {
        method,
        headers,
        signal: controller.signal,
      };

      // Forward body for non-GET requests
      if (method !== 'GET' && method !== 'HEAD') {
        options.body = await request.text();
      }

      const response = await fetch(laravelUrl.toString(), options);
      clearTimeout(timeoutId);

      // Build response with forwarded Set-Cookie headers
      const responseHeaders = new Headers();
      response.headers.forEach((value, key) => {
        if (key.toLowerCase() !== 'set-cookie') {
          responseHeaders.set(key, value);
        }
      });

      // Forward all Set-Cookie headers from Laravel
      const setCookieHeaders = response.headers.getSetCookie();
      setCookieHeaders.forEach((cookie) => {
        responseHeaders.append('set-cookie', cookie);
      });

      const responseData = await response.text();

      return new NextResponse(responseData, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof Error && error.name === 'AbortError') {
        return NextResponse.json({ error: 'Request timeout' }, { status: 504 });
      }
      throw error;
    }
  } catch (error) {
    console.error('[SPA Proxy Error]', error);
    return NextResponse.json(
      { error: 'Internal server error', message: 'Failed to proxy request' },
      { status: 500 }
    );
  }
}

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

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
