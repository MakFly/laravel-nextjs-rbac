<?php

namespace App\Http\Middleware;

use App\Helpers\HmacValidator;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;

/**
 * Middleware de protection BFF
 *
 * Vérifie que toutes les requêtes vers les routes versionnées (/api/v1/*)
 * sont signées avec HMAC par le BFF Next.js
 */
class BffHmacMiddleware
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next)
    {
        // Valider la signature HMAC
        $validation = HmacValidator::validate($request);

        if (!$validation['valid']) {
            Log::warning('BFF authentication failed', [
                'error' => $validation['error'],
                'path' => $request->path(),
                'ip' => $request->ip(),
            ]);

            return $this->errorResponse($validation['error']);
        }

        return $next($request);
    }

    /**
     * Génère une réponse d'erreur JSON
     */
    private function errorResponse(string $message): JsonResponse
    {
        return response()->json([
            'error' => $message,
            'message' => 'BFF authentication failed',
        ], 403);
    }
}
