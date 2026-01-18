<?php

namespace App\Helpers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

/**
 * HMAC validation helper for BFF requests
 *
 * Validates HMAC signatures of requests coming from Next.js BFF
 */
class HmacValidator
{
    /**
     * Timestamp tolerance in seconds (±5 minutes)
     */
    private const TIMESTAMP_TOLERANCE = 300;

    /**
     * Validates an HMAC request
     *
     * @param Request $request
     * @return array{valid: bool, error?: string}
     */
    public static function validate(Request $request): array
    {
        // 1. Validate presence of required headers
        $headersValidation = self::validateHeaders($request);
        if (!$headersValidation['valid']) {
            return $headersValidation;
        }

        // 2. Validate BFF ID
        $bffValidation = self::validateBffId($request);
        if (!$bffValidation['valid']) {
            return $bffValidation;
        }

        // 3. Validate timestamp
        $timestampValidation = self::validateTimestamp($request);
        if (!$timestampValidation['valid']) {
            return $timestampValidation;
        }

        // 4. Generate expected payload
        $payload = self::generatePayload($request);

        // 5. Validate signature
        return self::validateSignature($request, $payload);
    }

    /**
     * Validates presence of required headers
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
     * Validates BFF ID
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
     * Validates timestamp (anti-replay)
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
     * Generates payload for signature
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
     * Calculates body hash
     */
    private static function hashBody(Request $request): string
    {
        $body = $request->getContent();

        if (empty($body)) {
            return '';
        }

        // Normalize JSON: sort keys alphabetically
        $data = json_decode($body, true);
        if (is_array($data)) {
            $data = self::sortArrayKeys($data);
            $body = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }

        return hash('sha256', $body);
    }

    /**
     * Recursively sorts array keys alphabetically
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
     * Validates HMAC signature
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

        // Secure comparison to prevent timing attacks
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
