<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\Concerns\HasTokenCookies;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Laravel\Passport\Token;

class ImpersonationController extends Controller
{
    use HasTokenCookies;

    /**
     * Start impersonating a user.
     *
     * Saves the admin's current Passport token ID in an admin_token cookie,
     * then issues fresh Passport tokens for the target user.
     */
    public function impersonate(Request $request, User $user): JsonResponse
    {
        $admin = $request->user();

        if ($admin->id === $user->id) {
            return response()->json([
                'message' => 'You cannot impersonate yourself.',
            ], 403);
        }

        if ($user->hasRole('admin')) {
            return response()->json([
                'message' => 'You cannot impersonate an admin user.',
            ], 403);
        }

        // Save the admin's current token ID so we can restore later
        $adminTokenId = $admin->token()->id;

        // Create fresh Passport token for the target user
        $tokenResult = $user->createToken('impersonation', ['*']);
        $accessToken = $tokenResult->accessToken;
        $refreshToken = $tokenResult->token;

        $refreshToken->expires_at = now()->addDays(30);
        $refreshToken->save();

        $userData = AuthController::formatUser($user);
        $userData['is_impersonating'] = true;
        $userData['impersonator'] = [
            'id' => $admin->id,
            'name' => $admin->name,
            'email' => $admin->email,
        ];

        $response = response()->json([
            'data' => $userData,
            'message' => "Now impersonating {$user->name}",
        ]);

        // Set target user tokens + admin_token cookie
        $response = $this->withTokenCookies($response, $accessToken, $refreshToken->id);
        $adminCookie = $this->createTokenCookie(self::ADMIN_TOKEN_COOKIE, $adminTokenId, self::REFRESH_TOKEN_TTL);

        return $response->withCookie($adminCookie);
    }

    /**
     * Stop impersonating and return to admin account.
     *
     * Reads the admin_token cookie to find the original admin,
     * revokes the impersonation token, and issues fresh admin tokens.
     */
    public function stopImpersonating(Request $request): JsonResponse
    {
        $adminTokenId = $request->cookie(self::ADMIN_TOKEN_COOKIE);

        if (! $adminTokenId) {
            return response()->json([
                'message' => 'You are not impersonating anyone.',
            ], 400);
        }

        // Look up the admin from the saved token
        $adminToken = Token::find($adminTokenId);

        if (! $adminToken) {
            return $this->clearAllCookies(response()->json([
                'message' => 'Admin token not found. Session expired.',
            ], 401));
        }

        $admin = User::find($adminToken->user_id);

        if (! $admin) {
            return $this->clearAllCookies(response()->json([
                'message' => 'Admin user not found.',
            ], 401));
        }

        // Revoke the impersonation token (current user's token)
        $currentUser = $request->user();
        if ($currentUser && $currentUser->token()) {
            $currentUser->token()->revoke();
        }

        // Revoke the old admin token
        $adminToken->revoke();

        // Create fresh tokens for the admin
        $tokenResult = $admin->createToken('spa-auth', ['*']);
        $accessToken = $tokenResult->accessToken;
        $refreshToken = $tokenResult->token;

        $refreshToken->expires_at = now()->addDays(30);
        $refreshToken->save();

        $userData = AuthController::formatUser($admin);

        $response = response()->json([
            'data' => $userData,
            'message' => 'Stopped impersonating. Welcome back!',
        ]);

        // Set admin tokens + clear admin_token cookie
        $response = $this->withTokenCookies($response, $accessToken, $refreshToken->id);
        $expiredAdminCookie = $this->createExpiredCookie(self::ADMIN_TOKEN_COOKIE);

        return $response->withCookie($expiredAdminCookie);
    }

    private function clearAllCookies(JsonResponse $response): JsonResponse
    {
        $response = $this->clearTokenCookies($response);

        return $response->withCookie($this->createExpiredCookie(self::ADMIN_TOKEN_COOKIE));
    }
}
