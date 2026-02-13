<?php

namespace App\Services;

/**
 * Centralized cache key generation for consistent key naming across the application.
 */
class CacheKeyService
{
    private const PREFIX = 'onboarding';

    /**
     * Key for onboarding draft data.
     * Format: onboarding:{userId}:draft
     */
    public static function onboardingDraft(int $userId): string
    {
        return sprintf('%s:%d:draft', self::PREFIX, $userId);
    }

    /**
     * Key for onboarding status (computed from user + draft).
     * Format: onboarding:{userId}:status
     */
    public static function onboardingStatus(int $userId): string
    {
        return sprintf('%s:%d:status', self::PREFIX, $userId);
    }

    /**
     * Key for user operations data.
     * Format: onboarding:{userId}:operations
     */
    public static function userOperations(int $userId): string
    {
        return sprintf('%s:%d:operations', self::PREFIX, $userId);
    }

    /**
     * Key for distributed lock during onboarding operations.
     * Format: onboarding:{userId}:lock
     */
    public static function onboardingLock(int $userId): string
    {
        return sprintf('%s:%d:lock', self::PREFIX, $userId);
    }

    /**
     * Get all cache keys for a user (useful for debugging/invalidation).
     */
    public static function allForUser(int $userId): array
    {
        return [
            'draft' => self::onboardingDraft($userId),
            'status' => self::onboardingStatus($userId),
            'operations' => self::userOperations($userId),
            'lock' => self::onboardingLock($userId),
        ];
    }
}
