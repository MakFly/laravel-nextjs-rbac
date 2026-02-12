<?php

use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\Auth\OAuthController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\Admin\UserController as AdminUserController;
use App\Http\Controllers\Admin\RoleController;
use App\Http\Controllers\Admin\PermissionController;
use App\Http\Controllers\Admin\ImpersonationController;
use Illuminate\Support\Facades\Route;

// =========================================================================
// Public OAuth Routes (no HMAC, no prefix) - For OAuth providers
// These routes MUST remain directly accessible from outside
// =========================================================================

// 'web' middleware ensures session is available for SPA OAuth callback (Auth::login)
Route::middleware('web')->prefix('auth')->group(function () {
    Route::get('/{provider}/redirect', [OAuthController::class, 'redirect']);
    Route::get('/{provider}/callback', [OAuthController::class, 'callback']);
});

// =========================================================================
// Debug route (no HMAC) for testing
// =========================================================================

Route::get('/v1/debug/hmac', function (\Illuminate\Http\Request $request) {
    $timestamp = $request->header('X-BFF-Timestamp');
    $method = $request->method();
    $path = $request->path();
    $body = $request->getContent();

    $bodyHash = $body ? hash('sha256', $body) : '';
    $payload = "{$timestamp}:{$method}:{$path}:{$bodyHash}";
    $expectedSignature = hash_hmac('sha256', $payload, config('services.bff.secret'));

    return response()->json([
        'received' => [
            'path' => $request->path(),
            'method' => $request->method(),
            'timestamp' => $timestamp,
            'body' => $body,
            'body_hash' => $bodyHash,
            'payload' => $payload,
        ],
        'signature' => [
            'received' => $request->header('X-BFF-Signature'),
            'expected' => $expectedSignature,
            'match' => hash_equals($expectedSignature, $request->header('X-BFF-Signature')),
        ],
        'config' => [
            'secret_length' => strlen(config('services.bff.secret')),
            'secret_first_8' => substr(config('services.bff.secret'), 0, 8),
            'bff_id' => config('services.bff.id'),
        ],
    ]);
});

// =========================================================================
// BFF Routes (Passport + HMAC) - Access via BFF only
// All /api/v1/* routes require HMAC signature
// =========================================================================

Route::prefix('v1')
    ->middleware('bff.hmac')
    ->group(function () {

        // Public auth routes (no auth:api, but with HMAC)
        Route::prefix('auth')->group(function () {
            Route::post('/register', [AuthController::class, 'register']);
            Route::post('/login', [AuthController::class, 'login']);
            Route::get('/providers', [OAuthController::class, 'providers']);
        });

        // Protected routes (auth:api + HMAC)
        Route::middleware('auth:api')->group(function () {

            Route::prefix('auth')->group(function () {
                Route::post('/logout', [AuthController::class, 'logout']);
                Route::post('/refresh', [AuthController::class, 'refresh']);
            });

            Route::get('/me', [AuthController::class, 'me']);
            Route::get('/users', [UserController::class, 'index']);

            // Admin routes
            Route::middleware('role:admin')->prefix('admin')->group(function () {
                Route::get('/users', [AdminUserController::class, 'index']);
                Route::get('/users/{user}', [AdminUserController::class, 'show']);
                Route::post('/users/{user}/roles', [AdminUserController::class, 'assignRole']);
                Route::delete('/users/{user}/roles/{role}', [AdminUserController::class, 'removeRole']);

                Route::get('/roles', [RoleController::class, 'index']);
                Route::post('/roles', [RoleController::class, 'store']);
                Route::post('/roles/{role}/permissions', [RoleController::class, 'updatePermissions']);

                Route::get('/permissions', [PermissionController::class, 'index']);
            });

            // Permission-based route examples
            Route::middleware('permission:posts.read')->get('/posts', function () {
                return response()->json(['message' => 'Posts list - you have posts.read permission']);
            });

            Route::middleware('permission:posts.create')->post('/posts', function () {
                return response()->json(['message' => 'Create post - you have posts.create permission']);
            });
        });
    });

// =========================================================================
// SPA Routes (Sanctum session-based) - Access via Vue.js SPA
// All /api/spa/* routes use session auth via web guard
// =========================================================================

Route::prefix('spa')->group(function () {

    // Public auth routes
    Route::prefix('auth')->group(function () {
        Route::post('/login', [AuthController::class, 'spaLogin']);
        Route::post('/register', [AuthController::class, 'spaRegister']);
        Route::get('/providers', [OAuthController::class, 'providers']);
    });

    // Protected routes (session auth via web guard)
    Route::middleware('auth:web')->group(function () {

        Route::post('/auth/logout', [AuthController::class, 'spaLogout']);
        Route::get('/me', [AuthController::class, 'me']);
        Route::get('/users', [UserController::class, 'index']);

        // Admin routes
        Route::middleware('role:admin')->prefix('admin')->group(function () {
            Route::get('/users', [AdminUserController::class, 'index']);
            Route::get('/users/{user}', [AdminUserController::class, 'show']);
            Route::post('/users/{user}/roles', [AdminUserController::class, 'assignRole']);
            Route::delete('/users/{user}/roles/{role}', [AdminUserController::class, 'removeRole']);

            Route::get('/roles', [RoleController::class, 'index']);
            Route::post('/roles', [RoleController::class, 'store']);
            Route::post('/roles/{role}/permissions', [RoleController::class, 'updatePermissions']);

            Route::get('/permissions', [PermissionController::class, 'index']);

            // Impersonation (start) - requires admin role
            Route::post('/impersonate/{user}', [ImpersonationController::class, 'impersonate']);
        });

        // Stop impersonation - OUTSIDE admin group (impersonated user is not admin)
        Route::post('/admin/stop-impersonate', [ImpersonationController::class, 'stopImpersonating']);

        // Permission-based route examples
        Route::middleware('permission:posts.read')->get('/posts', function () {
            return response()->json(['message' => 'Posts list - you have posts.read permission']);
        });

        Route::middleware('permission:posts.create')->post('/posts', function () {
            return response()->json(['message' => 'Create post - you have posts.create permission']);
        });
    });
});
