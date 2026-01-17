/**
 * Types pour la sécurité BFF et HMAC
 */

/**
 * Headers HMAC requis pour communiquer avec Laravel
 */
export interface HmacHeaders {
  'X-BFF-Id': string;
  'X-BFF-Timestamp': string;
  'X-BFF-Signature': string;
}

/**
 * Erreur BFF standardisée
 */
export interface BffError {
  code: BffErrorCode;
  message: string;
  details?: unknown;
}

/**
 * Codes d'erreur BFF
 */
export enum BffErrorCode {
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  MISSING_HEADERS = 'MISSING_HEADERS',
  TIMESTAMP_EXPIRED = 'TIMESTAMP_EXPIRED',
  INVALID_BFF_ID = 'INVALID_BFF_ID',
  UPSTREAM_ERROR = 'UPSTREAM_ERROR',
  NETWORK_ERROR = 'NETWORK_ERROR',
  TIMEOUT = 'TIMEOUT',
}

/**
 * Exception BFF pour les erreurs contrôlées
 */
export class BffException extends Error {
  constructor(
    public code: BffErrorCode,
    message: string,
    public details?: unknown
  ) {
    super(message);
    this.name = 'BffException';
  }

  toJSON(): BffError {
    return {
      code: this.code,
      message: this.message,
      details: this.details,
    };
  }
}

/**
 * Configuration BFF
 */
export interface BffConfig {
  id: string;
  secret: string;
  apiUrl: string;
  timeout: number;
}

/**
 * Résultat d'une requête BFF
 */
export interface BffResponse<T = unknown> {
  data: T;
  status: number;
  headers: Headers;
}

/**
 * Options de requête BFF
 */
export interface BffRequestOptions {
  method: string;
  path: string;
  body?: unknown;
  headers?: Record<string, string>;
  timeout?: number;
}
