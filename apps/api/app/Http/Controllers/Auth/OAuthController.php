<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\OAuthProvider;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;

class OAuthController extends Controller
{
    protected array $providers = ['google', 'github'];

    public function redirect(string $provider, Request $request): RedirectResponse|JsonResponse
    {
        if (!in_array($provider, $this->providers)) {
            return response()->json(['error' => 'Provider not supported'], 400);
        }

        // Store client type in state for dual callback handling
        $state = $request->query('client', 'bff');

        return Socialite::driver($provider)
            ->stateless()
            ->with(['state' => $state])
            ->redirect();
    }

    public function callback(string $provider, Request $request): RedirectResponse
    {
        if (!in_array($provider, $this->providers)) {
            return redirect(config('app.frontend_url') . '/auth/error?message=Provider not supported');
        }

        try {
            $socialUser = Socialite::driver($provider)->stateless()->user();
        } catch (\Exception $e) {
            $errorUrl = $this->isSpaClient($request)
                ? config('app.vue_frontend_url') . '/auth/error?message=Authentication failed'
                : config('app.frontend_url') . '/auth/error?message=Authentication failed';
            return redirect($errorUrl);
        }

        $user = $this->findOrCreateUser($provider, $socialUser);

        // SPA flow: session-based login
        if ($this->isSpaClient($request)) {
            Auth::login($user);
            $request->session()->regenerate();

            return redirect(config('app.vue_frontend_url') . '/auth/callback?success=true');
        }

        // BFF flow: token-based login (Passport)
        $token = $user->createToken('oauth_token')->accessToken;
        $frontendUrl = config('app.frontend_url');

        return redirect("{$frontendUrl}/auth/callback?token={$token}");
    }

    public function providers(): JsonResponse
    {
        return response()->json([
            'data' => $this->providers,
        ]);
    }

    private function isSpaClient(Request $request): bool
    {
        return $request->query('state') === 'spa';
    }

    private function findOrCreateUser(string $provider, $socialUser): User
    {
        // Find existing OAuth provider link
        $oauthProvider = OAuthProvider::where('provider', $provider)
            ->where('provider_id', $socialUser->getId())
            ->first();

        if ($oauthProvider) {
            return $oauthProvider->user;
        }

        // Find user by email or create new
        $user = User::where('email', $socialUser->getEmail())->first();

        if (!$user) {
            $user = User::create([
                'name' => $socialUser->getName() ?? $socialUser->getNickname() ?? 'User',
                'email' => $socialUser->getEmail(),
                'email_verified_at' => now(),
                'password' => bcrypt(str()->random(32)),
            ]);

            $user->assignRole('user');
        }

        // Link OAuth provider
        $user->oauthProviders()->create([
            'provider' => $provider,
            'provider_id' => $socialUser->getId(),
            'avatar' => $socialUser->getAvatar(),
        ]);

        return $user;
    }
}
