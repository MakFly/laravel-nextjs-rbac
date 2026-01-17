/**
 * Module de signature HMAC pour BFF
 *
 * Ce module gère la génération de signatures HMAC pour sécuriser
 * les communications entre Next.js (BFF) et Laravel (API backend).
 */

import { createHash, createHmac } from 'crypto';
import type { HmacHeaders } from './types';

/**
 * Secret partagé HMAC (identique sur Laravel)
 * Doit être défini via la variable d'environnement BFF_HMAC_SECRET
 */
export const BFF_SECRET = process.env.BFF_HMAC_SECRET || '';

/**
 * ID du BFF (doit correspondre à la config Laravel)
 */
export const BFF_ID = process.env.BFF_ID || 'nextjs-bff-prod';

/**
 * Vérifie que le secret HMAC est configuré
 */
export function ensureHmacConfigured(): void {
  if (!BFF_SECRET) {
    throw new Error('BFF_HMAC_SECRET environment variable is not set');
  }
}

/**
 * Calcule le hash SHA256 du body
 * Les clés JSON sont triées par ordre alphabétique pour assurer
 * la cohérence avec l'implémentation Laravel
 */
export function hashBody(body: unknown): string {
  if (!body) {
    return '';
  }

  // Normaliser et trier les clés JSON
  const normalized = sortObjectKeys(body);
  const jsonString = JSON.stringify(normalized, (key, value) => {
    // Normaliser les formats pour la cohérence
    if (typeof value === 'number' && Number.isInteger(value)) {
      return value;
    }
    return value;
  }, 0);

  // Retirer les espaces pour la cohérence
  const compactJson = jsonString.replace(/\s/g, '');

  return createHash('sha256').update(compactJson, 'utf8').digest('hex');
}

/**
 * Trie récursivement les clés d'un objet par ordre alphabétique
 * pour assurer la cohérence de la signature avec Laravel
 */
function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(sortObjectKeys);
  }

  const sorted = Object.keys(obj as Record<string, unknown>)
    .sort()
    .reduce<Record<string, unknown>>((acc, key) => {
      acc[key] = sortObjectKeys((obj as Record<string, unknown>)[key]);
      return acc;
    }, {});

  return sorted;
}

/**
 * Génère les headers HMAC pour une requête
 *
 * @param method - Méthode HTTP (GET, POST, etc.)
 * @param path - Chemin de la requête (ex: /api/v1/auth/login)
 * @param body - Corps de la requête (optionnel)
 * @returns Headers HMAC requis + body normalisé à envoyer
 */
export function generateSignature(
  method: string,
  path: string,
  body?: unknown
): HmacHeaders & { normalizedBody?: string } {
  ensureHmacConfigured();

  // Timestamp en SECONDES (pas millisecondes) pour compatibilité Laravel
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const bodyHash = hashBody(body);

  // Format du payload: TIMESTAMP:METHOD:PATH:BODY_HASH
  const payload = `${timestamp}:${method}:${path}:${bodyHash}`;

  // Générer la signature HMAC-SHA256
  const signature = createHmac('sha256', BFF_SECRET)
    .update(payload, 'utf8')
    .digest('hex');

  const headers: HmacHeaders = {
    'X-BFF-Id': BFF_ID,
    'X-BFF-Timestamp': timestamp,
    'X-BFF-Signature': signature,
  };

  // Retourner aussi le body normalisé (trié) pour l'envoyer
  let normalizedBody: string | undefined;
  if (body !== null && body !== undefined) {
    const normalized = sortObjectKeys(body);
    normalizedBody = JSON.stringify(normalized);
  }

  return { ...headers, normalizedBody };
}

/**
 * Reconstruit le chemin Laravel depuis le chemin BFF
 *
 * Note: Les routes Laravel sont maintenant sous /api/v1/* avec le middleware HMAC.
 * Les seules routes sans HMAC sont les callbacks OAuth sous /api/auth/*.
 *
 * Cette fonction retourne le chemin tel quel car les routes BFF correspondent
 * exactement aux routes Laravel.
 */
export function buildLaravelPath(bffPath: string): string {
  // Les routes /api/v1/* dans Next.js correspondent aux routes /api/v1/* dans Laravel
  return bffPath;
}

/**
 * Extrait le chemin et la méthode depuis une URL Next.js
 * Pour une utilisation avec Next.js Request object
 */
export function extractPathFromUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.pathname;
  } catch {
    return url;
  }
}
