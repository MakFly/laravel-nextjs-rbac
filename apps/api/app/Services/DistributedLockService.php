<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

/**
 * Distributed lock service using Redis SETNX pattern.
 * Prevents race conditions during concurrent operations.
 */
class DistributedLockService
{
    /**
     * Attempt to acquire a distributed lock.
     *
     * @param string $key Lock key
     * @param int $ttl Time-to-live in seconds
     * @return string|null Lock token if acquired, null if failed
     */
    public function acquire(string $key, int $ttl = 30): ?string
    {
        $token = Str::random(32);
        $lockKey = "lock:{$key}";

        // Use SET with NX (not exists) and EX (expiry) for atomic lock acquisition
        $acquired = Cache::getStore()->getConnection()->set(
            $lockKey,
            $token,
            'EX',
            $ttl,
            'NX'
        );

        return $acquired ? $token : null;
    }

    /**
     * Release a distributed lock (only if we own it).
     *
     * @param string $key Lock key
     * @param string $token Lock token from acquire()
     */
    public function release(string $key, string $token): void
    {
        $lockKey = "lock:{$key}";

        // Lua script for atomic check-and-delete
        $lua = <<<'LUA'
            if redis.call("get", KEYS[1]) == ARGV[1] then
                return redis.call("del", KEYS[1])
            else
                return 0
            end
        LUA;

        Cache::getStore()->getConnection()->eval($lua, 1, $lockKey, $token);
    }

    /**
     * Execute a callback while holding a distributed lock.
     *
     * @param string $key Lock key
     * @param callable $callback Code to execute while holding lock
     * @param int $ttl Lock timeout in seconds
     * @param int $maxWait Maximum time to wait for lock in seconds
     * @return mixed Callback result
     * @throws \RuntimeException If lock cannot be acquired
     */
    public function withLock(string $key, callable $callback, int $ttl = 30, int $maxWait = 5): mixed
    {
        $startTime = time();
        $token = null;

        // Try to acquire lock with retry
        while (time() - $startTime < $maxWait) {
            $token = $this->acquire($key, $ttl);

            if ($token !== null) {
                break;
            }

            usleep(100000); // Wait 100ms before retry
        }

        if ($token === null) {
            throw new \RuntimeException("Could not acquire lock for key: {$key}");
        }

        try {
            return $callback();
        } finally {
            $this->release($key, $token);
        }
    }

    /**
     * Check if a lock is currently held.
     */
    public function isLocked(string $key): bool
    {
        $lockKey = "lock:{$key}";

        return Cache::getStore()->getConnection()->exists($lockKey) > 0;
    }
}
