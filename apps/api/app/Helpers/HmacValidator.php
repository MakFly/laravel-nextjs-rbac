<?php

namespace App\Helpers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

/**
 * Helper de validation HMAC pour les requêtes BFF
 *
 * Valide les signatures HMAC des requêtes provenant du BFF Next.js
 */
class HmacValidator
{
    /**
     * Tolérance de timestamp en secondes (±5 minutes)
     */
    private const TIMESTAMP_TOLERANCE = 300;

    /**
     * Valide une requête HMAC
     *
     * @param Request $request
     * @return array{valid: bool, error?: string}
     */
    public static function validate(Request $request): array
    {
        // 1. Valider la présence des headers requis
        $headersValidation = self::validateHeaders($request);
        if (!$headersValidation['valid']) {
            return $headersValidation;
        }

        // 2. Valider l'ID du BFF
        $bffValidation = self::validateBffId($request);
        if (!$bffValidation['valid']) {
            return $bffValidation;
        }

        // 3. Valider le timestamp
        $timestampValidation = self::validateTimestamp($request);
        if (!$timestampValidation['valid']) {
            return $timestampValidation;
        }

        // 4. Générer le payload attendu
        $payload = self::generatePayload($request);

        // 5. Valider la signature
        return self::validateSignature($request, $payload);
    }

    /**
     * Valide la présence des headers requis
     */
    private static function validateHeaders(Request $request): array
    {
        $requiredHeaders = ['X-BFF-Id', 'X-BFF-Timestamp', 'X-BFF-Signature'];
        $missingHeaders = [];

        foreach ($requiredHeaders as $header) {
            if (!$request->hasHeader($header)) {
                $missingHeaders[] = $header;
            }
        }

        if (!empty($missingHeaders)) {
            return [
                'valid' => false,
                'error' => 'Missing required headers: ' . implode(', ', $missingHeaders),
            ];
        }

        return ['valid' => true];
    }

    /**
     * Valide l'ID du BFF
     */
    private static function validateBffId(Request $request): array
    {
        $bffId = $request->header('X-BFF-Id');
        $expectedId = config('services.bff.id');

        if ($bffId !== $expectedId) {
            Log::warning('BFF ID mismatch', [
                'expected' => $expectedId,
                'received' => $bffId,
                'ip' => $request->ip(),
            ]);

            return [
                'valid' => false,
                'error' => 'Invalid BFF ID',
            ];
        }

        return ['valid' => true];
    }

    /**
     * Valide le timestamp (anti-replay)
     */
    private static function validateTimestamp(Request $request): array
    {
        $timestamp = (int) $request->header('X-BFF-Timestamp');
        $now = now()->timestamp;
        $diff = abs($now - $timestamp);

        if ($diff > self::TIMESTAMP_TOLERANCE) {
            Log::warning('BFF timestamp validation failed', [
                'timestamp' => $timestamp,
                'now' => $now,
                'diff' => $diff,
                'ip' => $request->ip(),
            ]);

            return [
                'valid' => false,
                'error' => 'Timestamp validation failed',
            ];
        }

        return ['valid' => true];
    }

    /**
     * Génère le payload pour la signature
     *
     * Format: TIMESTAMP:METHOD:PATH:BODY_HASH
     */
    private static function generatePayload(Request $request): string
    {
        $timestamp = $request->header('X-BFF-Timestamp');
        $method = $request->method();
        $path = $request->path();
        $bodyHash = self::hashBody($request);

        return "{$timestamp}:{$method}:{$path}:{$bodyHash}";
    }

    /**
     * Calcule le hash du body
     */
    private static function hashBody(Request $request): string
    {
        $body = $request->getContent();

        if (empty($body)) {
            return '';
        }

        // Normaliser le JSON: trier les clés par ordre alphabétique
        $data = json_decode($body, true);
        if (is_array($data)) {
            $data = self::sortArrayKeys($data);
            $body = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }

        return hash('sha256', $body);
    }

    /**
     * Trie récursivement les clés d'un tableau par ordre alphabétique
     */
    private static function sortArrayKeys(array $array): array
    {
        ksort($array);

        foreach ($array as $key => $value) {
            if (is_array($value)) {
                $array[$key] = self::sortArrayKeys($value);
            }
        }

        return $array;
    }

    /**
     * Valide la signature HMAC
     */
    private static function validateSignature(Request $request, string $payload): array
    {
        $providedSignature = $request->header('X-BFF-Signature');
        $secret = config('services.bff.secret');

        if (empty($secret)) {
            Log::error('BFF secret not configured');

            return [
                'valid' => false,
                'error' => 'BFF authentication misconfigured',
            ];
        }

        $expectedSignature = hash_hmac('sha256', $payload, $secret);

        // Comparaison sécurisée pour éviter les timing attacks
        if (!hash_equals($expectedSignature, $providedSignature)) {
            Log::warning('BFF signature validation failed', [
                'payload' => $payload,
                'expected' => $expectedSignature,
                'received' => $providedSignature,
                'ip' => $request->ip(),
            ]);

            return [
                'valid' => false,
                'error' => 'Invalid signature',
            ];
        }

        return ['valid' => true];
    }
}
