<?php

use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\Auth\OAuthController;
use Illuminate\Support\Facades\Route;

// =========================================================================
// Public OAuth Routes (sans HMAC, sans v1) - Pour OAuth providers
// Ces routes DOIVENT rester accessibles directement depuis l'extérieur
// =========================================================================

Route::prefix('auth')->group(function () {
    // OAuth Routes (redirections depuis providers externes)
    Route::get('/{provider}/redirect', [OAuthController::class, 'redirect']);
    Route::get('/{provider}/callback', [OAuthController::class, 'callback']);
});

// =========================================================================
// Route de debug (SANS HMAC) pour tester
// =========================================================================

Route::get('/v1/debug/hmac', function (\Illuminate\Http\Request $request) {
    // Recréer le calcul de signature Laravel
    $timestamp = $request->header('X-BFF-Timestamp');
    $method = $request->method();
    $path = $request->path();
    $body = $request->getContent();

    // Calculer le body hash comme Laravel le fait
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
// Versioned API Routes (AVEC HMAC) - Accès via BFF uniquement
// Toutes les routes /api/v1/* nécessitent la signature HMAC
// =========================================================================

Route::prefix('v1')
    ->middleware('bff.hmac')
    ->group(function () {

        // -------------------------------------------------------------------
        // Routes d'auth publiques (sans auth:api, mais avec HMAC)
        // Le BFF Next.js peut appeler ces routes avec HMAC
        // -------------------------------------------------------------------
        Route::prefix('auth')->group(function () {
            Route::post('/register', [AuthController::class, 'register']);
            Route::post('/login', [AuthController::class, 'login']);
            Route::get('/providers', [OAuthController::class, 'providers']);
        });

        // -------------------------------------------------------------------
        // Routes protégées (nécessitent auth:api + HMAC)
        // -------------------------------------------------------------------
        Route::middleware('auth:api')->group(function () {

            // Auth routes
            Route::prefix('auth')->group(function () {
                Route::post('/logout', [AuthController::class, 'logout']);
                Route::post('/refresh', [AuthController::class, 'refresh']);
            });

            // Current User
            Route::get('/me', [AuthController::class, 'me']);

            // Users list (accessible par tous les users authentifiés)
            Route::get('/users', function () {
                return response()->json([
                    'data' => \App\Models\User::with('roles')->get(),
                ]);
            });

            // -------------------------------------------------------------------
            // Admin Routes (role: admin)
            // -------------------------------------------------------------------
            Route::middleware('role:admin')->prefix('admin')->group(function () {
                // Users Management
                Route::get('/users', function () {
                    return response()->json([
                        'data' => \App\Models\User::with('roles')->paginate(15),
                    ]);
                });

                Route::get('/users/{user}', function (\App\Models\User $user) {
                    return response()->json([
                        'data' => $user->load('roles.permissions'),
                    ]);
                });

                Route::post('/users/{user}/roles', function (\App\Models\User $user, \Illuminate\Http\Request $request) {
                    $validated = $request->validate(['role' => 'required|string|exists:roles,slug']);
                    $user->assignRole($validated['role']);
                    return response()->json(['message' => 'Role assigned', 'data' => $user->load('roles')]);
                });

                Route::delete('/users/{user}/roles/{role}', function (\App\Models\User $user, \App\Models\Role $role) {
                    $user->removeRole($role);
                    return response()->json(['message' => 'Role removed']);
                });

                // Roles Management
                Route::get('/roles', function () {
                    return response()->json([
                        'data' => \App\Models\Role::with('permissions')->get(),
                    ]);
                });

                Route::post('/roles', function (\Illuminate\Http\Request $request) {
                    $validated = $request->validate([
                        'name' => 'required|string|max:255',
                        'slug' => 'required|string|max:255|unique:roles',
                        'description' => 'nullable|string',
                    ]);
                    $role = \App\Models\Role::create($validated);
                    return response()->json(['data' => $role], 201);
                });

                // Permissions Management
                Route::get('/permissions', function () {
                    return response()->json([
                        'data' => \App\Models\Permission::all(),
                    ]);
                });

                Route::post('/roles/{role}/permissions', function (\App\Models\Role $role, \Illuminate\Http\Request $request) {
                    $validated = $request->validate(['permissions' => 'required|array']);
                    $role->permissions()->sync($validated['permissions']);
                    return response()->json(['message' => 'Permissions updated', 'data' => $role->load('permissions')]);
                });
            });

            // -------------------------------------------------------------------
            // Permission-based Routes Examples
            // -------------------------------------------------------------------
            Route::middleware('permission:posts.read')->get('/posts', function () {
                return response()->json(['message' => 'Posts list - you have posts.read permission']);
            });

            Route::middleware('permission:posts.create')->post('/posts', function () {
                return response()->json(['message' => 'Create post - you have posts.create permission']);
            });
        });
    });
