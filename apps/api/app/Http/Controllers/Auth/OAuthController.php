<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\OAuthProvider;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;

class OAuthController extends Controller
{
    protected array $providers = ['google', 'github'];

    public function redirect(string $provider): RedirectResponse|JsonResponse
    {
        if (!in_array($provider, $this->providers)) {
            return response()->json(['error' => 'Provider not supported'], 400);
        }

        return Socialite::driver($provider)->stateless()->redirect();
    }

    public function callback(string $provider, Request $request): RedirectResponse
    {
        if (!in_array($provider, $this->providers)) {
            return redirect(config('app.frontend_url') . '/auth/error?message=Provider not supported');
        }

        try {
            $socialUser = Socialite::driver($provider)->stateless()->user();
        } catch (\Exception $e) {
            return redirect(config('app.frontend_url') . '/auth/error?message=Authentication failed');
        }

        // Find existing OAuth provider link
        $oauthProvider = OAuthProvider::where('provider', $provider)
            ->where('provider_id', $socialUser->getId())
            ->first();

        if ($oauthProvider) {
            $user = $oauthProvider->user;
        } else {
            // Find user by email or create new
            $user = User::where('email', $socialUser->getEmail())->first();

            if (!$user) {
                $user = User::create([
                    'name' => $socialUser->getName() ?? $socialUser->getNickname() ?? 'User',
                    'email' => $socialUser->getEmail(),
                    'email_verified_at' => now(),
                    'password' => bcrypt(str()->random(32)),
                ]);

                // Assign default role
                $user->assignRole('user');
            }

            // Link OAuth provider
            $user->oauthProviders()->create([
                'provider' => $provider,
                'provider_id' => $socialUser->getId(),
                'avatar' => $socialUser->getAvatar(),
            ]);
        }

        // Create access token
        $token = $user->createToken('oauth_token')->accessToken;

        // Redirect to frontend with token
        $frontendUrl = config('app.frontend_url');
        return redirect("{$frontendUrl}/auth/callback?token={$token}");
    }

    public function providers(): JsonResponse
    {
        return response()->json([
            'data' => $this->providers,
        ]);
    }
}
