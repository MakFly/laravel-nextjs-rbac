/**
 * Sanctum CSRF Proxy Route Handler
 *
 * Proxies /sanctum/* requests to Laravel so the browser can
 * obtain CSRF cookies through the Next.js proxy.
 */

import { type NextRequest, NextResponse } from 'next/server';

const LARAVEL_API_URL = process.env.LARAVEL_API_URL || 'http://localhost:8000';

interface RouteParams {
  params: Promise<{ path: string[] }>;
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const pathSegments = (await params).path;
  const laravelPath = `/sanctum/${pathSegments.join('/')}`;
  const laravelUrl = new URL(laravelPath, LARAVEL_API_URL);

  const cookieHeader = request.headers.get('cookie') || '';

  const headers: HeadersInit = {
    'Accept': 'application/json',
    'Referer': process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3001',
    'Origin': process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3001',
  };

  if (cookieHeader) {
    headers['Cookie'] = cookieHeader;
  }

  const response = await fetch(laravelUrl.toString(), {
    method: 'GET',
    headers,
  });

  // Build response with forwarded Set-Cookie headers
  const responseHeaders = new Headers();
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() !== 'set-cookie') {
      responseHeaders.set(key, value);
    }
  });

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
}

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
