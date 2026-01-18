/**
 * HMAC signing module for BFF
 *
 * This module handles HMAC signature generation to secure
 * communications between Next.js (BFF) and Laravel (backend API).
 */

import { createHash, createHmac } from 'crypto';
import type { HmacHeaders } from './types';

/**
 * Shared HMAC secret (same on Laravel)
 * Must be set via BFF_HMAC_SECRET environment variable
 */
export const BFF_SECRET = process.env.BFF_HMAC_SECRET || '';

/**
 * BFF ID (must match Laravel config)
 */
export const BFF_ID = process.env.BFF_ID || 'nextjs-bff-prod';

/**
 * Verifies that HMAC secret is configured
 */
export function ensureHmacConfigured(): void {
  if (!BFF_SECRET) {
    throw new Error('BFF_HMAC_SECRET environment variable is not set');
  }
}

/**
 * Calculates SHA256 hash of body
 * JSON keys are sorted alphabetically to ensure
 * consistency with Laravel implementation
 */
export function hashBody(body: unknown): string {
  if (!body) {
    return '';
  }

  // Normalize and sort JSON keys
  const normalized = sortObjectKeys(body);
  const jsonString = JSON.stringify(normalized, (key, value) => {
    // Normalize formats for consistency
    if (typeof value === 'number' && Number.isInteger(value)) {
      return value;
    }
    return value;
  }, 0);

  // Remove spaces for consistency
  const compactJson = jsonString.replace(/\s/g, '');

  return createHash('sha256').update(compactJson, 'utf8').digest('hex');
}

/**
 * Recursively sorts object keys alphabetically
 * to ensure signature consistency with Laravel
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
 * Generates HMAC headers for a request
 *
 * @param method - HTTP method (GET, POST, etc.)
 * @param path - Request path (ex: /api/v1/auth/login)
 * @param body - Request body (optional)
 * @returns Required HMAC headers + normalized body to send
 */
export function generateSignature(
  method: string,
  path: string,
  body?: unknown
): HmacHeaders & { normalizedBody?: string } {
  ensureHmacConfigured();

  // Timestamp in SECONDS (not milliseconds) for Laravel compatibility
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const bodyHash = hashBody(body);

  // Payload format: TIMESTAMP:METHOD:PATH:BODY_HASH
  const payload = `${timestamp}:${method}:${path}:${bodyHash}`;

  // Generate HMAC-SHA256 signature
  const signature = createHmac('sha256', BFF_SECRET)
    .update(payload, 'utf8')
    .digest('hex');

  const headers: HmacHeaders = {
    'X-BFF-Id': BFF_ID,
    'X-BFF-Timestamp': timestamp,
    'X-BFF-Signature': signature,
  };

  // Also return normalized (sorted) body to send
  let normalizedBody: string | undefined;
  if (body !== null && body !== undefined) {
    const normalized = sortObjectKeys(body);
    normalizedBody = JSON.stringify(normalized);
  }

  return { ...headers, normalizedBody };
}

/**
 * Rebuilds Laravel path from BFF path
 *
 * Note: Laravel routes are now under /api/v1/* with HMAC middleware.
 * Only OAuth callbacks under /api/auth/* don't require HMAC.
 *
 * This function returns the path as-is because BFF routes correspond
 * exactly to Laravel routes.
 */
export function buildLaravelPath(bffPath: string): string {
  // /api/v1/* routes in Next.js correspond to /api/v1/* routes in Laravel
  return bffPath;
}

/**
 * Extracts path and method from a Next.js URL
 * For use with Next.js Request object
 */
export function extractPathFromUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.pathname;
  } catch {
    return url;
  }
}
