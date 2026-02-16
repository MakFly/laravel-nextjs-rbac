<?php

namespace App\Http\Controllers\Concerns;

use Illuminate\Http\JsonResponse;
use Symfony\Component\HttpFoundation\Cookie;

trait HasTokenCookies
{
    protected const ACCESS_TOKEN_COOKIE = 'access_token';

    protected const REFRESH_TOKEN_COOKIE = 'refresh_token';

    protected const ADMIN_TOKEN_COOKIE = 'admin_token';

    protected const ACCESS_TOKEN_TTL = 21600; // 6 hours in seconds

    protected const REFRESH_TOKEN_TTL = 2592000; // 30 days in seconds

    protected function withTokenCookies(JsonResponse $response, string $accessToken, string $refreshToken): JsonResponse
    {
        $accessCookie = $this->createTokenCookie(self::ACCESS_TOKEN_COOKIE, $accessToken, self::ACCESS_TOKEN_TTL);
        $refreshCookie = $this->createTokenCookie(self::REFRESH_TOKEN_COOKIE, $refreshToken, self::REFRESH_TOKEN_TTL);

        return $response->withCookie($accessCookie)->withCookie($refreshCookie);
    }

    protected function clearTokenCookies(JsonResponse $response): JsonResponse
    {
        $accessCookie = $this->createExpiredCookie(self::ACCESS_TOKEN_COOKIE);
        $refreshCookie = $this->createExpiredCookie(self::REFRESH_TOKEN_COOKIE);

        return $response->withCookie($accessCookie)->withCookie($refreshCookie);
    }

    protected function createTokenCookie(string $name, string $value, int $ttl): Cookie
    {
        $domain = $this->getCookieDomain();
        $secure = config('app.env') === 'production';
        $sameSite = $secure ? 'none' : 'lax';

        return Cookie::create(
            $name,
            $value,
            time() + $ttl,
            '/',
            $domain,
            $secure,
            true,
            false,
            $sameSite
        );
    }

    protected function createExpiredCookie(string $name): Cookie
    {
        $domain = $this->getCookieDomain();
        $secure = config('app.env') === 'production';

        return Cookie::create(
            $name,
            '',
            time() - 3600,
            '/',
            $domain,
            $secure,
            true,
            false,
            'lax'
        );
    }

    private function getCookieDomain(): ?string
    {
        return null;
    }
}
