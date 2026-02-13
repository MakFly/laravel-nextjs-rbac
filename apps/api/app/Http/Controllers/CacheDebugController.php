<?php

namespace App\Http\Controllers;

use App\Services\OnboardingCacheService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Debug controller for cache inspection and manipulation.
 * Only accessible to authenticated users for their own data.
 */
class CacheDebugController extends Controller
{
    public function __construct(
        private OnboardingCacheService $cacheService
    ) {}

    /**
     * Get cache debug information for the authenticated user.
     *
     * GET /api/v1/debug/cache (BFF)
     * GET /api/spa/debug/cache (SPA)
     */
    public function show(Request $request): JsonResponse
    {
        $userId = $request->user()->id;
        $debug = $this->cacheService->debug($userId);

        return response()->json([
            'data' => $debug,
        ]);
    }

    /**
     * Force cache warmup for the authenticated user.
     *
     * POST /api/v1/debug/cache/warmup (BFF)
     * POST /api/spa/debug/cache/warmup (SPA)
     */
    public function warmup(Request $request): JsonResponse
    {
        $userId = $request->user()->id;
        $this->cacheService->warmup($userId);

        return response()->json([
            'message' => 'Cache warmed up successfully',
            'data' => $this->cacheService->debug($userId),
        ]);
    }

    /**
     * Invalidate cache for the authenticated user.
     *
     * DELETE /api/v1/debug/cache (BFF)
     * DELETE /api/spa/debug/cache (SPA)
     */
    public function invalidate(Request $request): JsonResponse
    {
        $userId = $request->user()->id;
        $this->cacheService->invalidate($userId);

        return response()->json([
            'message' => 'Cache invalidated successfully',
            'data' => $this->cacheService->debug($userId),
        ]);
    }
}
