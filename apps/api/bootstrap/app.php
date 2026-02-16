<?php

use App\Http\Middleware\BffHmacMiddleware;
use App\Http\Middleware\EnsureOnboardingComplete;
use App\Http\Middleware\PassportCookieMiddleware;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        channels: __DIR__.'/../routes/channels.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // Passport tokens are stored in HttpOnly cookies (SameSite=Lax + Secure in prod).
        // Exclude them from Laravel's cookie encryption to avoid read-back mismatch on refresh.
        $middleware->encryptCookies(except: [
            'access_token',
            'refresh_token',
            'admin_token',
        ]);

        // Ensure PassportCookieMiddleware runs BEFORE Authenticate.
        // Without this, Laravel's middleware priority reorders auth:api
        // before passport.cookie, so the Bearer token is never set.
        $middleware->priority([
            \Illuminate\Cookie\Middleware\EncryptCookies::class,
            \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
            \Illuminate\Routing\Middleware\ThrottleRequests::class,
            \Illuminate\Routing\Middleware\ThrottleRequestsWithRedis::class,
            PassportCookieMiddleware::class,
            \Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests::class,
            \Illuminate\Auth\Middleware\Authorize::class,
        ]);

        $middleware->alias([
            'role' => \Spatie\Permission\Middleware\RoleMiddleware::class,
            'permission' => \Spatie\Permission\Middleware\PermissionMiddleware::class,
            'role_or_permission' => \Spatie\Permission\Middleware\RoleOrPermissionMiddleware::class,
            'bff.hmac' => BffHmacMiddleware::class,
            'onboarding.complete' => EnsureOnboardingComplete::class,
            'passport.cookie' => PassportCookieMiddleware::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
