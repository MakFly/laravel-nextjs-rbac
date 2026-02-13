/**
 * Server Actions for cache debug (Sanctum SPA mode)
 *
 * Uses Laravel Sanctum session-based auth via server-side helper.
 */

'use server';

import { laravelRequest, initCsrfServer } from './laravel';

export interface CacheKeyInfo {
  key: string;
  exists: boolean;
  ttl_seconds: number | null;
  data: unknown | null;
}

export interface DatabaseInfo {
  draft: unknown | null;
  kyc_profile: unknown | null;
  user_operation: unknown | null;
  user: unknown | null;
}

export interface CacheDiff {
  in_cache_only: string[];
  in_db_only: string[];
  different: string[];
}

export interface CacheDebugData {
  user_id: number;
  keys: {
    draft: CacheKeyInfo;
    status: CacheKeyInfo;
    operations: CacheKeyInfo;
  };
  database: DatabaseInfo;
  diff: CacheDiff;
}

export interface CacheDebugResponse {
  data: CacheDebugData;
}

export interface CacheMessageResponse {
  message: string;
  data: CacheDebugData;
}

/**
 * Get cache debug information for the current user
 */
export async function getCacheDebugAction(): Promise<CacheDebugResponse> {
  return laravelRequest<CacheDebugResponse>('/debug/cache');
}

/**
 * Force cache warmup for the current user
 */
export async function warmupCacheAction(): Promise<CacheMessageResponse> {
  await initCsrfServer();
  return laravelRequest<CacheMessageResponse>('/debug/cache/warmup', {
    method: 'POST',
  });
}

/**
 * Invalidate cache for the current user
 */
export async function invalidateCacheAction(): Promise<CacheMessageResponse> {
  await initCsrfServer();
  return laravelRequest<CacheMessageResponse>('/debug/cache', {
    method: 'DELETE',
  });
}
