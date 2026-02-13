# Onboarding Caching Strategy - Redis

## Overview

This document describes the Redis caching strategy for onboarding drafts and user operations. The caching layer provides:
- Reduced database load for frequent draft reads
- Faster response times during onboarding wizard navigation
- Warm-up at login for seamless user experience

**Architecture Pattern:** Cache-aside (lazy loading) with write-through for consistency.

---

## Cache Keys Convention

### Key Structure

```
{prefix}:{entity}:{identifier}:{subkey}
```

| Component | Value | Example |
|-----------|-------|---------|
| prefix | `laravel-cache-` (from `CACHE_PREFIX`) | `laravel-cache-` |
| entity | `onboarding` or `operations` | `onboarding` |
| identifier | `{userId}` | `42` |
| subkey | Optional context | `draft`, `status` |

### Defined Keys

| Key Pattern | Description | Example |
|-------------|-------------|---------|
| `onboarding:{userId}:draft` | Full draft data JSON | `onboarding:42:draft` |
| `onboarding:{userId}:status` | Status + current step | `onboarding:42:status` |
| `operations:{userId}:profile` | User operation settings | `operations:42:profile` |
| `onboarding:{userId}:locks` | Distributed lock for concurrent saves | `onboarding:42:locks` |

### Key Generation Helper

```php
// app/Services/CacheKeyService.php
class CacheKeyService
{
    public static function onboardingDraft(int $userId): string
    {
        return "onboarding:{$userId}:draft";
    }

    public static function onboardingStatus(int $userId): string
    {
        return "onboarding:{$userId}:status";
    }

    public static function userOperations(int $userId): string
    {
        return "operations:{$userId}:profile";
    }

    public static function onboardingLock(int $userId): string
    {
        return "onboarding:{$userId}:locks";
    }
}
```

---

## TTL (Time-to-Live) Configuration

### TTL Values

| Key | TTL | Rationale |
|-----|-----|-----------|
| `onboarding:{userId}:draft` | **24 hours** (86400s) | Drafts are transient; long enough for session, short enough to auto-expire abandoned onboarding |
| `onboarding:{userId}:status` | **7 days** (604800s) | Status rarely changes after completion; can be cached longer |
| `operations:{userId}:profile` | **1 hour** (3600s) | Short TTL - operations may be updated by admin/backend processes |
| `onboarding:{userId}:locks` | **30 seconds** | Lock auto-expires to prevent deadlocks |

### Configuration

```php
// config/onboarding.php
return [
    'cache' => [
        'draft_ttl' => env('ONBOARDING_DRAFT_TTL', 86400),      // 24h
        'status_ttl' => env('ONBOARDING_STATUS_TTL', 604800),   // 7 days
        'operations_ttl' => env('OPERATIONS_TTL', 3600),        // 1h
        'lock_ttl' => env('ONBOARDING_LOCK_TTL', 30),           // 30s
    ],
];
```

---

## Invalidation Strategy

### Write-Through Pattern

Every database write **immediately** updates the cache to maintain consistency.

```
┌──────────────────────────────────────────────────────────────┐
│                    WRITE FLOW (saveDraft)                     │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Acquire distributed lock                                 │
│     Redis::set(lock_key, 1, 'EX', 30, 'NX')                 │
│                                                              │
│  2. Update database                                          │
│     DB::transaction → update onboarding_drafts               │
│                                                              │
│  3. Update cache (write-through)                             │
│     Cache::put(draft_key, $data, TTL)                        │
│                                                              │
│  4. Invalidate dependent caches                              │
│     Cache::forget(status_key)                                │
│                                                              │
│  5. Release lock                                             │
│     Redis::del(lock_key)                                     │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Invalidation Triggers

| Event | Action | Keys Affected |
|-------|--------|---------------|
| `saveDraft()` | Update cache | `onboarding:{userId}:draft`, forget `status` |
| `finalize()` | Delete cache | `onboarding:{userId}:draft`, update `status` |
| User login | Warm-up | All keys |
| User logout | Optional cleanup | All keys (optional) |
| Admin updates operations | Invalidate | `operations:{userId}:profile` |

### Cache Tags (Alternative)

For bulk invalidation, use cache tags:

```php
Cache::tags(['user:' . $userId, 'onboarding'])->flush();
```

---

## Warm-up at Login

### Strategy

Pre-populate onboarding caches during login to ensure instant access to draft data when the user reaches the onboarding page.

### Implementation

```php
// app/Services/OnboardingCacheService.php
class OnboardingCacheService
{
    public function warmup(int $userId): void
    {
        // Use pipeline for atomic multi-get/set
        Redis::pipeline(function ($pipe) use ($userId) {
            // 1. Warm up status
            $status = $this->getStatusFromDb($userId);
            $pipe->setex(
                CacheKeyService::onboardingStatus($userId),
                config('onboarding.cache.status_ttl'),
                json_encode($status)
            );

            // 2. Warm up draft if in progress
            if ($status['onboarding_status'] === 'in_progress') {
                $draft = $this->getDraftFromDb($userId);
                if ($draft) {
                    $pipe->setex(
                        CacheKeyService::onboardingDraft($userId),
                        config('onboarding.cache.draft_ttl'),
                        json_encode($draft)
                    );
                }
            }

            // 3. Warm up operations if completed
            if ($status['onboarding_status'] === 'completed') {
                $operations = $this->getOperationsFromDb($userId);
                if ($operations) {
                    $pipe->setex(
                        CacheKeyService::userOperations($userId),
                        config('onboarding.cache.operations_ttl'),
                        json_encode($operations)
                    );
                }
            }
        });
    }

    private function getStatusFromDb(int $userId): array
    {
        return User::where('id', $userId)
            ->select(['onboarding_status', 'onboarding_step'])
            ->first()
            ->toArray();
    }

    private function getDraftFromDb(int $userId): ?array
    {
        $draft = OnboardingDraft::where('user_id', $userId)->first();
        return $draft ? ['data' => $draft->data, 'updated_at' => $draft->updated_at] : null;
    }

    private function getOperationsFromDb(int $userId): ?array
    {
        return UserOperation::where('user_id', $userId)->first()?->toArray();
    }
}
```

### Hook into Login

```php
// app/Http/Controllers/Auth/AuthController.php
public function login(LoginRequest $request): JsonResponse
{
    // ... existing authentication logic ...

    $user = Auth::user();

    // Warm up onboarding cache
    app(OnboardingCacheService::class)->warmup($user->id);

    return response()->json([
        'user' => $this->formatUser($user),
    ]);
}
```

---

## Fallback Strategy (Redis Down)

### Graceful Degradation

When Redis is unavailable, the system must continue to function using database-only operations.

```
┌──────────────────────────────────────────────────────────────┐
│                    FALLBACK FLOW                              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  try {                                                       │
│      $data = Cache::get($key);                               │
│  } catch (RedisConnectionException $e) {                     │
│      Log::warning('Redis unavailable, falling back to DB');  │
│      $data = $this->getFromDatabase($userId);                │
│  }                                                           │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Implementation Pattern

```php
// app/Services/OnboardingService.php (with caching)
class OnboardingService
{
    public function __construct(
        private readonly OnboardingCacheService $cacheService
    ) {}

    public function getDraft(int $userId): ?OnboardingDraft
    {
        try {
            // Try cache first
            $cached = $this->cacheService->getDraft($userId);
            if ($cached !== null) {
                return $this->hydrateDraft($cached);
            }
        } catch (\Throwable $e) {
            // Log but continue - don't break user flow
            Log::warning('Cache read failed, falling back to DB', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
            ]);
        }

        // Cache miss or unavailable - read from DB
        $draft = OnboardingDraft::where('user_id', $userId)->first();

        // Try to populate cache for next read
        if ($draft) {
            try {
                $this->cacheService->setDraft($userId, $draft);
            } catch (\Throwable $e) {
                // Ignore cache write failures
                Log::warning('Cache write failed', [
                    'user_id' => $userId,
                    'error' => $e->getMessage(),
                ]);
            });
        }

        return $draft;
    }

    public function saveDraft(int $userId, int $step, array $data): OnboardingDraft
    {
        // 1. Always write to DB first (source of truth)
        $draft = $this->saveDraftToDatabase($userId, $step, $data);

        // 2. Try to update cache (best effort)
        try {
            $this->cacheService->setDraft($userId, $draft);
            $this->cacheService->invalidateStatus($userId);
        } catch (\Throwable $e) {
            Log::warning('Cache update failed after DB write', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
            ]);
        }

        return $draft;
    }
}
```

### Circuit Breaker Pattern

For production, consider a circuit breaker to avoid hammering an unhealthy Redis:

```php
// app/Services/CacheHealthService.php
class CacheHealthService
{
    private int $failures = 0;
    private ?Carbon $lastFailure = null;
    private const THRESHOLD = 5;
    private const RESET_AFTER_SECONDS = 60;

    public function isAvailable(): bool
    {
        // Check if circuit is open
        if ($this->failures >= self::THRESHOLD) {
            if ($this->lastFailure->diffInSeconds(now()) > self::RESET_AFTER_SECONDS) {
                $this->reset();
                return true;
            }
            return false;
        }

        try {
            Redis::ping();
            return true;
        } catch (\Throwable $e) {
            $this->recordFailure();
            return false;
        }
    }

    private function recordFailure(): void
    {
        $this->failures++;
        $this->lastFailure = now();
    }

    private function reset(): void
    {
        $this->failures = 0;
        $this->lastFailure = null;
    }
}
```

---

## Distributed Locking

### Purpose

Prevent race conditions when multiple requests attempt to update the same draft simultaneously.

### Implementation

```php
// app/Services/DistributedLockService.php
class DistributedLockService
{
    public function acquire(string $key, int $ttl = 30): bool
    {
        return (bool) Redis::set($key, 1, 'EX', $ttl, 'NX');
    }

    public function release(string $key): void
    {
        Redis::del($key);
    }

    public function withLock(string $key, callable $callback, int $ttl = 30): mixed
    {
        if (!$this->acquire($key, $ttl)) {
            throw new \RuntimeException('Unable to acquire lock: ' . $key);
        }

        try {
            return $callback();
        } finally {
            $this->release($key);
        }
    }
}

// Usage in OnboardingService
public function saveDraft(int $userId, int $step, array $data): OnboardingDraft
{
    $lockKey = CacheKeyService::onboardingLock($userId);

    return $this->lockService->withLock($lockKey, function () use ($userId, $step, $data) {
        // ... save logic ...
    });
}
```

---

## Monitoring & Metrics

### Key Metrics to Track

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `cache.hit_rate` | % of requests served from cache | < 70% |
| `cache.latency_p99` | 99th percentile cache latency | > 50ms |
| `cache.fallback_rate` | % of requests falling back to DB | > 5% |
| `cache.memory_usage` | Redis memory consumption | > 80% of maxmemory |

### Laravel Telescope Integration

```php
// Monitor cache operations
Cache::remember($key, $ttl, function () {
    // This will be logged in Telescope
    return $this->expensiveOperation();
});
```

### Custom Metrics

```php
// app/Services/CacheMetricsService.php
class CacheMetricsService
{
    public function recordHit(string $key): void
    {
        Cache::increment('metrics:cache:hits');
        Cache::increment("metrics:cache:hits:{$this->getEntityType($key)}");
    }

    public function recordMiss(string $key): void
    {
        Cache::increment('metrics:cache:misses');
    }

    public function recordFallback(string $key, string $reason): void
    {
        Cache::increment('metrics:cache:fallbacks');
        Log::info('Cache fallback', ['key' => $key, 'reason' => $reason]);
    }

    public function getHitRate(): float
    {
        $hits = Cache::get('metrics:cache:hits', 0);
        $misses = Cache::get('metrics:cache:misses', 0);
        $total = $hits + $misses;

        return $total > 0 ? round($hits / $total * 100, 2) : 0;
    }
}
```

---

## Configuration Summary

### Environment Variables

```env
# apps/api/.env

# Cache driver
CACHE_STORE=redis
CACHE_PREFIX=laravel-cache-

# Redis connection
REDIS_CLIENT=predis
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=null
REDIS_CACHE_CONNECTION=cache

# Onboarding-specific TTLs (seconds)
ONBOARDING_DRAFT_TTL=86400      # 24h
ONBOARDING_STATUS_TTL=604800    # 7 days
OPERATIONS_TTL=3600             # 1h
ONBOARDING_LOCK_TTL=30          # 30s
```

### Docker Compose

```yaml
# docker-compose.yml
services:
  redis:
    image: redis:7-alpine
    container_name: rbac_redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

volumes:
  redis_data:
```

---

## Implementation Checklist

- [ ] Create `CacheKeyService` for centralized key generation
- [ ] Create `OnboardingCacheService` with warmup/get/set methods
- [ ] Modify `OnboardingService` to use cache layer
- [ ] Add distributed locking for concurrent draft updates
- [ ] Hook warmup into `AuthController::login()`
- [ ] Add fallback handling with graceful degradation
- [ ] Implement circuit breaker for Redis health
- [ ] Add cache metrics and monitoring
- [ ] Configure TTL values in `config/onboarding.php`
- [ ] Add Redis health check to Docker Compose
- [ ] Document runbook for Redis failover scenarios

---

## Related Documentation

- [Onboarding Workflow](./ONBOARDING_WORKFLOW.md) - Main onboarding flow and API
- [Reverb OrderBook](./REVERB_ORDERBOOK.md) - Real-time events architecture
