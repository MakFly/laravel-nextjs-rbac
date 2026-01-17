/**
 * Server Actions pour l'authentification
 *
 * Ces actions utilisent le BFF pour communiquer avec Laravel.
 * L'authentification utilise maintenant des cookies HttpOnly.
 */

'use server';

import { cookies } from 'next/headers';
import type { User, LoginCredentials, RegisterData, AuthTokens, ApiResponse } from '@rbac/types';

/**
 * URL de base du BFF Next.js
 */
const BFF_URL = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

/**
 * Erreur BFF personnalisée
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
 * Effectue une requête au BFF
 */
async function bffRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<ApiResponse<T>> {
  const url = `${BFF_URL}${endpoint}`;

  // Récupérer le cookie pour les requêtes authentifiées
  const cookieStore = await cookies();
  const authToken = cookieStore.get('auth_token');

  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...options.headers,
  };

  // Pour les requêtes server-to-server, on doit passer le cookie manuellement
  // car credentials: 'include' ne fonctionne que côté navigateur
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

  // Gérer les cookies de retour (nouveau token, etc.)
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
        maxAge: 60 * 60 * 24 * 15, // 15 jours
      });
    }
  });

  return data;
}

/**
 * Inscription d'un nouvel utilisateur
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
 * Connexion d'un utilisateur
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
 * Déconnexion
 */
export async function logoutAction(): Promise<void> {
  try {
    await bffRequest('/api/v1/auth/logout', {
      method: 'POST',
    });
  } finally {
    // Supprimer le cookie côté client
    const cookieStore = await cookies();
    cookieStore.delete('auth_token');
  }
}

/**
 * Rafraîchir le token
 */
export async function refreshTokenAction(): Promise<ApiResponse<AuthTokens>> {
  return bffRequest<AuthTokens>('/api/v1/auth/refresh', {
    method: 'POST',
  });
}

/**
 * Récupérer l'utilisateur actuel
 *
 * Note: Retourne null si l'utilisateur n'est pas connecté
 * (plutôt que de lancer une erreur)
 */
export async function getCurrentUserAction(): Promise<User | null> {
  try {
    const response = await bffRequest<User>('/api/v1/me');
    return response.data;
  } catch (error) {
    // Si l'utilisateur n'est pas connecté (401) ou si le BFF rejette (403),
    // on retourne null silencieusement
    if (error instanceof BffRequestError) {
      if (error.statusCode === 401 || error.statusCode === 403) {
        return null;
      }
    }
    throw error;
  }
}

/**
 * Récupérer la liste des providers OAuth
 */
export async function getOAuthProvidersAction(): Promise<ApiResponse<string[]>> {
  return bffRequest<string[]>('/api/v1/auth/providers');
}

/**
 * Récupérer l'URL de redirection OAuth
 */
export async function getOAuthUrlAction(provider: string): Promise<{ url: string }> {
  const response = await bffRequest<{ redirect_url: string }>(
    `/api/v1/auth/${provider}/redirect`
  );

  return { url: response.data.redirect_url };
}
