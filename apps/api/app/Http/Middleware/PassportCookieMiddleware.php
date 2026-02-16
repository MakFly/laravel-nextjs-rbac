<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Reads the access_token from an HttpOnly cookie and sets it
 * as a Bearer token in the Authorization header.
 *
 * This allows Passport's auth:api guard to authenticate
 * requests where tokens are stored in secure HttpOnly cookies
 * rather than being sent explicitly by the client.
 */
class PassportCookieMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $accessToken = $request->cookie('access_token');

        if ($accessToken && ! $request->bearerToken()) {
            $request->headers->set('Authorization', 'Bearer '.$accessToken);
        }

        return $next($request);
    }
}
