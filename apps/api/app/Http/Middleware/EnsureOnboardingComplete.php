<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureOnboardingComplete
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if ($user && $user->onboarding_status !== 'completed') {
            return response()->json([
                'message' => 'Onboarding not completed',
                'redirect' => '/onboarding',
                'current_step' => $user->onboarding_step,
            ], 403);
        }

        return $next($request);
    }
}
