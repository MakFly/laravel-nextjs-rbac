<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
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

        if (!Auth::attempt($validated)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $user = User::where('email', $validated['email'])->firstOrFail();
        $token = $user->createToken('auth_token')->accessToken;

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

        // Add impersonation state when session is available (SPA routes)
        if ($request->hasSession() && $request->session()->has('impersonator_id')) {
            $impersonator = User::find($request->session()->get('impersonator_id'));
            $userData['is_impersonating'] = true;
            $userData['impersonator'] = $impersonator ? [
                'id' => $impersonator->id,
                'name' => $impersonator->name,
                'email' => $impersonator->email,
            ] : null;
        }

        return response()->json([
            'data' => $userData,
        ]);
    }

    // =========================================================================
    // SPA Auth (Sanctum session-based)
    // =========================================================================

    public function spaLogin(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if (!Auth::attempt($validated)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $request->session()->regenerate();

        return response()->json([
            'data' => [
                'user' => self::formatUser(Auth::user()),
            ],
            'message' => 'Login successful',
        ]);
    }

    public function spaRegister(Request $request): JsonResponse
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

        Auth::login($user);
        $request->session()->regenerate();

        return response()->json([
            'data' => [
                'user' => self::formatUser($user),
            ],
            'message' => 'User registered successfully',
        ], 201);
    }

    public function spaLogout(Request $request): JsonResponse
    {
        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->json([
            'message' => 'Successfully logged out',
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
            'roles' => $user->roles->map(fn($role) => [
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
