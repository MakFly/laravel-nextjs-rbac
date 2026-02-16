<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Concerns\HasTokenCookies;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\OnboardingCacheService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Validation\ValidationException;
use Laravel\Passport\Token;

class AuthController extends Controller
{
    use HasTokenCookies;

    public function __construct(
        private OnboardingCacheService $cacheService
    ) {}

    public function register(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'onboarding_status' => 'pending',
            'onboarding_step' => 1,
        ]);

        // Assign default role
        $user->assignRole('user');

        $token = $user->createToken('auth_token')->accessToken;

        return response()->json([
            'data' => [
                'user' => self::formatUser($user),
                'access_token' => $token,
                'token_type' => 'Bearer',
            ],
            'message' => 'User registered successfully',
        ], 201);
    }

    public function login(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if (! Auth::attempt($validated)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $user = User::where('email', $validated['email'])->firstOrFail();
        $token = $user->createToken('auth_token')->accessToken;

        // Warmup onboarding cache
        $this->cacheService->warmup($user->id);

        return response()->json([
            'data' => [
                'user' => self::formatUser($user),
                'access_token' => $token,
                'token_type' => 'Bearer',
            ],
            'message' => 'Login successful',
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        $request->user()->token()->revoke();

        return response()->json([
            'message' => 'Successfully logged out',
        ]);
    }

    public function me(Request $request): JsonResponse
    {
        $userData = self::formatUser($request->user());

        // Check for impersonation via admin_token cookie
        $adminTokenId = $request->cookie(self::ADMIN_TOKEN_COOKIE);

        if ($adminTokenId) {
            $adminToken = Token::find($adminTokenId);

            if ($adminToken && ! $adminToken->revoked) {
                $impersonator = User::find($adminToken->user_id);
                $userData['is_impersonating'] = true;
                $userData['impersonator'] = $impersonator ? [
                    'id' => $impersonator->id,
                    'name' => $impersonator->name,
                    'email' => $impersonator->email,
                ] : null;
            }
        }

        return response()->json([
            'data' => $userData,
        ]);
    }

    // =========================================================================
    // BFF Auth (Passport token-based)
    // =========================================================================

    public function refresh(Request $request): JsonResponse
    {
        $user = $request->user();
        $user->token()->revoke();

        $token = $user->createToken('auth_token')->accessToken;

        return response()->json([
            'data' => [
                'access_token' => $token,
                'token_type' => 'Bearer',
            ],
        ]);
    }

    // =========================================================================
    // Token-based Auth with Cookies (OWASP compliant)
    // =========================================================================

    public function tokenLogin(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $user = User::where('email', $validated['email'])->first();

        if (! $user || ! Hash::check($validated['password'], $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $tokenResult = $user->createToken('spa-auth', ['*']);
        $accessToken = $tokenResult->accessToken;
        $refreshToken = $tokenResult->token;

        $refreshToken->expires_at = now()->addDays(30);
        $refreshToken->save();

        $this->cacheService->warmup($user->id);

        $response = response()->json([
            'data' => [
                'user' => self::formatUser($user),
            ],
        ]);

        return $this->withTokenCookies($response, $accessToken, $refreshToken->id);
    }

    public function tokenRefresh(Request $request): JsonResponse
    {
        $refreshTokenId = $request->cookie(self::REFRESH_TOKEN_COOKIE);

        if (! $refreshTokenId) {
            return response()->json([
                'message' => 'Refresh token not provided.',
            ], 401);
        }

        // Look up user from the stored token ID (no auth middleware needed)
        $token = Token::find($refreshTokenId);

        if (! $token || $token->revoked) {
            return $this->clearTokenCookies(response()->json([
                'message' => 'Invalid refresh token',
            ], 401));
        }

        $user = User::find($token->user_id);

        if (! $user) {
            return $this->clearTokenCookies(response()->json([
                'message' => 'User not found',
            ], 401));
        }

        // Revoke old token
        $token->revoke();

        $newTokenResult = $user->createToken('spa-auth-refresh', ['*']);
        $newAccessToken = $newTokenResult->accessToken;
        $newRefreshToken = $newTokenResult->token;

        $newRefreshToken->expires_at = now()->addDays(30);
        $newRefreshToken->save();

        $response = response()->json([
            'data' => [
                'user' => self::formatUser($user),
            ],
        ]);

        return $this->withTokenCookies($response, $newAccessToken, $newRefreshToken->id);
    }

    public function tokenRegister(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'onboarding_status' => 'pending',
            'onboarding_step' => 1,
        ]);

        $user->assignRole('user');

        $clientId = config('app.passport_client_id', env('PASSPORT_CLIENT_ID'));
        $clientSecret = config('app.passport_client_secret', env('PASSPORT_CLIENT_SECRET'));

        $tokenResponse = Http::accept('application/json')
            ->asForm()
            ->post(config('app.url').'/oauth/token', [
                'grant_type' => 'password',
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'username' => $validated['email'],
                'password' => $validated['password'],
                'scope' => '',
            ]);

        if (! $tokenResponse->successful()) {
            // User created but token grant failed — caller should login manually
            return response()->json([
                'data' => [
                    'user' => self::formatUser($user),
                ],
                'message' => 'User registered successfully. Please login.',
            ], 201);
        }

        $tokenData = $tokenResponse->json();

        $response = $this->buildTokenResponse($user, $tokenData['access_token'], $tokenData['refresh_token']);

        return $this->withTokenCookies($response, $tokenData['access_token'], $tokenData['refresh_token']);
    }

    public function tokenLogout(Request $request): JsonResponse
    {
        $user = $request->user();

        if ($user && $user->token()) {
            $user->token()->revoke();
        }

        $response = $this->clearTokenCookies(response()->json([
            'message' => 'Successfully logged out',
        ]));

        // Also clear admin_token if present
        $adminTokenId = $request->cookie(self::ADMIN_TOKEN_COOKIE);
        if ($adminTokenId) {
            $response = $response->withCookie($this->createExpiredCookie(self::ADMIN_TOKEN_COOKIE));
        }

        return $response;
    }

    private function buildTokenResponse(?User $user, string $accessToken, string $refreshToken): JsonResponse
    {
        $userData = $user ? self::formatUser($user) : null;

        return response()->json([
            'data' => [
                'user' => $userData,
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'token_type' => 'Bearer',
                'expires_in' => self::ACCESS_TOKEN_TTL,
            ],
            'message' => 'Login successful',
        ]);
    }

    public static function formatUser(User $user): array
    {
        $user->load('roles.permissions');

        return [
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'email_verified_at' => $user->email_verified_at,
            'onboarding_status' => $user->onboarding_status ?? 'pending',
            'onboarding_step' => $user->onboarding_step ?? 1,
            'created_at' => $user->created_at,
            'updated_at' => $user->updated_at,
            'roles' => $user->roles->map(fn ($role) => [
                'id' => $role->id,
                'name' => $role->name,
                'slug' => $role->name,  // Spatie has no slug, map name→slug
            ]),
            'permissions' => $user->getAllPermissions()->map(function ($perm) {
                $parts = explode('.', $perm->name);

                return [
                    'id' => $perm->id,
                    'name' => $perm->name,
                    'slug' => $perm->name,
                    'resource' => $parts[0] ?? '',
                    'action' => $parts[1] ?? '',
                ];
            })->values(),
        ];
    }
}
