<?php

namespace App\Services;

use App\Models\KycProfile;
use App\Models\OnboardingDraft;
use App\Models\User;
use App\Models\UserOperation;
use Illuminate\Support\Facades\Cache;

/**
 * Cache service for onboarding data with read-through and write-through patterns.
 */
class OnboardingCacheService
{
    public function __construct(
        private DistributedLockService $lockService
    ) {}

    /**
     * Get draft data from cache (cache-first with fallback to DB).
     */
    public function getDraft(int $userId): ?array
    {
        $key = CacheKeyService::onboardingDraft($userId);
        $ttl = config('onboarding.cache.draft_ttl', 86400);

        return Cache::remember($key, $ttl, function () use ($userId) {
            $draft = OnboardingDraft::where('user_id', $userId)->first();
            return $draft?->data;
        });
    }

    /**
     * Set draft data in cache (write-through to DB as well).
     */
    public function setDraft(int $userId, array $data): void
    {
        $lockKey = CacheKeyService::onboardingLock($userId);

        $this->lockService->withLock($lockKey, function () use ($userId, $data) {
            $key = CacheKeyService::onboardingDraft($userId);
            $ttl = config('onboarding.cache.draft_ttl', 86400);

            // Update database
            $draft = OnboardingDraft::firstOrCreate(
                ['user_id' => $userId],
                ['data' => []]
            );
            $draft->update(['data' => $data]);

            // Update cache
            Cache::put($key, $data, $ttl);
        });
    }

    /**
     * Get onboarding status from cache (computed from user + draft).
     */
    public function getStatus(int $userId): array
    {
        $key = CacheKeyService::onboardingStatus($userId);
        $ttl = config('onboarding.cache.status_ttl', 604800);

        return Cache::remember($key, $ttl, function () use ($userId) {
            $user = User::find($userId);

            if (!$user) {
                return [
                    'status' => 'not_found',
                    'step' => 0,
                    'has_draft' => false,
                ];
            }

            $hasDraft = OnboardingDraft::where('user_id', $userId)->exists();
            $hasKycProfile = KycProfile::where('user_id', $userId)->exists();

            return [
                'status' => $user->onboarding_status ?? 'pending',
                'step' => $user->onboarding_step ?? 1,
                'has_draft' => $hasDraft,
                'has_kyc_profile' => $hasKycProfile,
            ];
        });
    }

    /**
     * Get user operations from cache.
     */
    public function getOperations(int $userId): ?array
    {
        $key = CacheKeyService::userOperations($userId);
        $ttl = config('onboarding.cache.operations_ttl', 3600);

        return Cache::remember($key, $ttl, function () use ($userId) {
            $operation = UserOperation::where('user_id', $userId)->first();

            if (!$operation) {
                return null;
            }

            return [
                'account_type' => $operation->account_type,
                'preferred_currency' => $operation->preferred_currency,
                'iban' => $operation->iban,
                'preferred_cryptocurrency' => $operation->preferred_cryptocurrency,
                'wallet_address' => $operation->wallet_address,
                'initial_transaction_amount' => $operation->initial_transaction_amount,
            ];
        });
    }

    /**
     * Warmup cache for a user (preload all onboarding-related data).
     */
    public function warmup(int $userId): void
    {
        // Warmup draft
        $this->getDraft($userId);

        // Warmup status
        $this->getStatus($userId);

        // Warmup operations
        $this->getOperations($userId);
    }

    /**
     * Invalidate all cache for a user.
     */
    public function invalidate(int $userId): void
    {
        Cache::forget(CacheKeyService::onboardingDraft($userId));
        Cache::forget(CacheKeyService::onboardingStatus($userId));
        Cache::forget(CacheKeyService::userOperations($userId));
    }

    /**
     * Get debug information about cached data for a user.
     */
    public function debug(int $userId): array
    {
        $keys = CacheKeyService::allForUser($userId);
        $result = [
            'user_id' => $userId,
            'keys' => [],
            'database' => [],
            'diff' => [
                'in_cache_only' => [],
                'in_db_only' => [],
                'different' => [],
            ],
        ];

        // Check each key
        foreach (['draft', 'status', 'operations'] as $type) {
            $key = $keys[$type];
            $exists = Cache::has($key);
            $ttl = $exists ? Cache::getStore()->getConnection()->ttl($key) : null;

            // Get cached data
            $cachedData = null;
            if ($exists) {
                $cachedData = Cache::get($key);
            }

            $result['keys'][$type] = [
                'key' => $key,
                'exists' => $exists,
                'ttl_seconds' => $ttl > 0 ? $ttl : null,
                'data' => $cachedData,
            ];
        }

        // Get database data
        $result['database']['draft'] = OnboardingDraft::where('user_id', $userId)->first()?->data;
        $result['database']['kyc_profile'] = KycProfile::where('user_id', $userId)->first()?->toArray();
        $result['database']['user_operation'] = UserOperation::where('user_id', $userId)->first()?->toArray();
        $result['database']['user'] = User::find($userId)?->only([
            'id', 'name', 'email', 'onboarding_status', 'onboarding_step',
        ]);

        // Compute diff
        $this->computeDiff($result);

        return $result;
    }

    /**
     * Compute differences between cache and database.
     */
    private function computeDiff(array &$result): void
    {
        // Check draft diff
        $cachedDraft = $result['keys']['draft']['data'] ?? null;
        $dbDraft = $result['database']['draft'] ?? null;

        if ($cachedDraft !== null && $dbDraft === null) {
            $result['diff']['in_cache_only'][] = 'draft';
        } elseif ($cachedDraft === null && $dbDraft !== null) {
            $result['diff']['in_db_only'][] = 'draft';
        } elseif ($cachedDraft !== $dbDraft) {
            $result['diff']['different'][] = 'draft';
        }
    }
}
