<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Onboarding Cache Configuration
    |--------------------------------------------------------------------------
    |
    | Configure TTL (Time To Live) for various onboarding cache entries.
    | All values are in seconds.
    |
    */

    'cache' => [
        // Draft data TTL (24 hours by default)
        'draft_ttl' => env('ONBOARDING_DRAFT_TTL', 86400),

        // Status cache TTL (7 days by default - rarely changes)
        'status_ttl' => env('ONBOARDING_STATUS_TTL', 604800),

        // User operations cache TTL (1 hour by default)
        'operations_ttl' => env('OPERATIONS_TTL', 3600),

        // Distributed lock TTL (30 seconds by default)
        'lock_ttl' => env('ONBOARDING_LOCK_TTL', 30),
    ],
];
