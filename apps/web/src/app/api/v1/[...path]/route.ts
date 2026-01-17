/**
 * BFF Route Handler
 *
 * Ce handler catch-all proxy toutes les requêtes /api/v1/* vers Laravel
 * en ajoutant automatiquement la signature HMAC.
 */

import { type NextRequest, NextResponse } from 'next/server';
import { generateSignature, buildLaravelPath } from '@/lib/security/hmac';
import { BffException, BffErrorCode, type HmacHeaders } from '@/lib/security/types';
import { cookies } from 'next/headers';

/**
 * Configuration Laravel
 */
const LARAVEL_API_URL = process.env.LARAVEL_API_URL || 'http://localhost:8000';
const BFF_TIMEOUT = 30000; // 30 secondes

/**
 * Type pour les params de route dynamique Next.js 14+
 */
interface RouteParams {
  params: Promise<{ path: string[] }>;
}

/**
 * Regex pour valider les segments de path (alphanumériques, tirets, underscores uniquement)
 */
const SAFE_PATH_SEGMENT = /^[a-zA-Z0-9_-]+$/;

/**
 * Valide les segments de path pour prévenir les attaques SSRF/Path Traversal
 * @throws {BffException} si le path contient des segments dangereux
 */
function validatePathSegments(segments: string[]): void {
  for (const segment of segments) {
    // Rejeter les segments vides
    if (!segment) {
      throw new BffException(BffErrorCode.INVALID_SIGNATURE, 'Invalid path: empty segment');
    }

    // Rejeter path traversal
    if (segment === '..' || segment === '.') {
      throw new BffException(BffErrorCode.INVALID_SIGNATURE, 'Invalid path: traversal not allowed');
    }

    // Rejeter les URLs absolues
    if (segment.includes('://') || segment.startsWith('//')) {
      throw new BffException(BffErrorCode.INVALID_SIGNATURE, 'Invalid path: absolute URLs not allowed');
    }

    // Valider le format du segment (alphanumériques, tirets, underscores)
    if (!SAFE_PATH_SEGMENT.test(segment)) {
      throw new BffException(BffErrorCode.INVALID_SIGNATURE, 'Invalid path: forbidden characters');
    }
  }
}

/**
 * Fonction principale de proxy vers Laravel
 */
async function proxyRequest(
  request: NextRequest,
  method: string,
  paramsPromise: RouteParams['params']
): Promise<NextResponse> {
  try {
    // Extraire le chemin depuis les params
    const params = await paramsPromise;
    const pathSegments = params.path;

    // Valider les segments pour prévenir SSRF
    validatePathSegments(pathSegments);

    const bffPath = `/api/v1/${pathSegments.join('/')}`;

    // Reconstruire le chemin Laravel (SANS le slash au début pour correspondre à Laravel)
    const laravelPath = buildLaravelPath(bffPath).replace(/^\//, '');
    const laravelUrl = new URL(laravelPath, LARAVEL_API_URL);

    // Double vérification: s'assurer que l'URL finale pointe vers Laravel
    const expectedHost = new URL(LARAVEL_API_URL).host;
    if (laravelUrl.host !== expectedHost) {
      throw new BffException(BffErrorCode.INVALID_SIGNATURE, 'Invalid request: host mismatch');
    }

    // Récupérer le body pour la signature
    const clonedRequest = request.clone();
    let body: unknown = null;

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      try {
        const contentType = request.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          body = await clonedRequest.json();
        }
      } catch {
        // Pas de body ou non-JSON
      }
    }

    // Générer la signature HMAC avec le body parsé
    const hmacResult = generateSignature(method, laravelPath, body);
    const hmacHeaders: HmacHeaders = {
      'X-BFF-Id': hmacResult['X-BFF-Id'],
      'X-BFF-Timestamp': hmacResult['X-BFF-Timestamp'],
      'X-BFF-Signature': hmacResult['X-BFF-Signature'],
    };

    const cookieStore = await cookies();

    // Préparer les headers pour Laravel
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...hmacHeaders,
    };

    // Routes publiques qui ne nécessitent pas d'authentification
    const publicRoutes = [
      'api/v1/auth/login',
      'api/v1/auth/register',
      'api/v1/auth/providers',
    ];
    const isPublicRoute = publicRoutes.some((route) => laravelPath.startsWith(route));

    // Transférer le token d'authentification si présent (Bearer token pour Laravel)
    const authToken = cookieStore.get('auth_token')?.value;

    if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    } else if (!isPublicRoute) {
      return NextResponse.json(
        { error: 'Unauthorized', message: 'No auth token found' },
        { status: 401 }
      );
    }

    // Créer l'AbortController pour le timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), BFF_TIMEOUT);

    try {
      // Préparer les options de fetch
      const options: RequestInit = {
        method,
        headers,
        signal: controller.signal,
      };

      // Envoyer le body normalisé (trié) pour correspondre à la signature
      if (hmacResult.normalizedBody !== undefined) {
        options.body = hmacResult.normalizedBody;
      }

      // Copier les query params
      request.nextUrl.searchParams.forEach((value, key) => {
        laravelUrl.searchParams.set(key, value);
      });

      // Effectuer la requête vers Laravel
      const response = await fetch(laravelUrl.toString(), options);

      clearTimeout(timeoutId);

      // Récupérer les cookies de la réponse (nouveau token, etc.)
      const setCookieHeaders = response.headers.getSetCookie();
      const responseHeaders = new Headers();

      // Copier les headers de réponse importants
      response.headers.forEach((value, key) => {
        if (key !== 'set-cookie') {
          responseHeaders.set(key, value);
        }
      });

      // Transférer les cookies depuis Laravel
      setCookieHeaders.forEach((cookie) => {
        responseHeaders.append('set-cookie', cookie);
      });

      // Récupérer le body de la réponse
      const responseData = await response.text();

      // Créer la réponse Next.js
      const nextResponse = new NextResponse(responseData, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });

      // Si Laravel retourne un access_token, définir un cookie HttpOnly
      try {
        const jsonData = JSON.parse(responseData);
        if (jsonData.data?.access_token) {
          const token = jsonData.data.access_token;
          const expiresAt = new Date();
          expiresAt.setDate(expiresAt.getDate() + 15); // 15 jours

          // Définir le cookie HttpOnly
          nextResponse.cookies.set('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/',
            expires: expiresAt,
          });
        }
      } catch {
        // Pas de JSON ou pas de token
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
    // Gestion des erreurs
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
 * Handlers pour chaque méthode HTTP
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
 * Configurer les options de route
 */
export const runtime = 'nodejs'; // Nécessaire pour crypto
export const dynamic = 'force-dynamic'; // Désactiver le cache pour les routes sensibles
