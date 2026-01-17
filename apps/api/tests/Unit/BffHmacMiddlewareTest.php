<?php

namespace Tests\Unit;

use App\Http\Middleware\BffHmacMiddleware;
use App\Helpers\HmacValidator;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Mockery;
use Tests\TestCase;

/**
 * Tests unitaires pour BffHmacMiddleware
 */
class BffHmacMiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Configurer le secret BFF pour les tests
        config(['services.bff.id' => 'nextjs-bff-prod']);
        config(['services.bff.secret' => 'test-secret-key-for-hmac-validation']);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    /**
     * Génère une signature HMAC valide pour les tests
     */
    private function generateValidSignature(string $timestamp, string $method, string $path, ?string $body = null): string
    {
        $bodyHash = $body ? hash('sha256', $body) : '';
        $payload = "{$timestamp}:{$method}:{$path}:{$bodyHash}";

        return hash_hmac('sha256', $payload, config('services.bff.secret'));
    }

    public function test_middleware_returns_403_when_validation_fails(): void
    {
        $request = Request::create('/api/v1/me', 'GET');
        // Pas de headers HMAC

        $middleware = new BffHmacMiddleware();
        $response = $middleware->handle($request, fn ($req) => new Response('OK'));

        $this->assertEquals(403, $response->status());
        $json = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('error', $json);
        $this->assertEquals('BFF authentication failed', $json['message']);
    }

    public function test_middleware_passes_request_with_valid_hmac(): void
    {
        $timestamp = (string) now()->timestamp;
        $signature = $this->generateValidSignature($timestamp, 'GET', '/api/v1/me');

        $request = Request::create('/api/v1/me', 'GET');
        $request->headers->set('X-BFF-Id', config('services.bff.id'));
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', $signature);

        $middleware = new BffHmacMiddleware();
        $response = $middleware->handle($request, fn ($req) => new Response('Success'));

        $this->assertEquals(200, $response->status());
        $this->assertEquals('Success', $response->getContent());
    }

    public function test_middleware_returns_403_for_invalid_bff_id(): void
    {
        $timestamp = (string) now()->timestamp;
        $signature = $this->generateValidSignature($timestamp, 'GET', '/api/v1/me');

        $request = Request::create('/api/v1/me', 'GET');
        $request->headers->set('X-BFF-Id', 'wrong-bff-id');
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', $signature);

        $middleware = new BffHmacMiddleware();
        $response = $middleware->handle($request, fn ($req) => new Response('OK'));

        $this->assertEquals(403, $response->status());
    }

    public function test_middleware_returns_403_for_expired_timestamp(): void
    {
        $timestamp = (string) now()->subMinutes(10)->timestamp;
        $signature = $this->generateValidSignature($timestamp, 'GET', '/api/v1/me');

        $request = Request::create('/api/v1/me', 'GET');
        $request->headers->set('X-BFF-Id', config('services.bff.id'));
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', $signature);

        $middleware = new BffHmacMiddleware();
        $response = $middleware->handle($request, fn ($req) => new Response('OK'));

        $this->assertEquals(403, $response->status());
    }

    public function test_middleware_returns_403_for_invalid_signature(): void
    {
        $timestamp = (string) now()->timestamp;

        $request = Request::create('/api/v1/me', 'GET');
        $request->headers->set('X-BFF-Id', config('services.bff.id'));
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', 'wrong-signature');

        $middleware = new BffHmacMiddleware();
        $response = $middleware->handle($request, fn ($req) => new Response('OK'));

        $this->assertEquals(403, $response->status());
    }

    public function test_middleware_passes_request_with_post_body(): void
    {
        $body = json_encode([
            'email' => 'test@example.com',
            'password' => 'secret',
        ]);

        $sortedBody = json_encode([
            'email' => 'test@example.com',
            'password' => 'secret',
        ]);
        $bodyHash = hash('sha256', $sortedBody);
        $timestamp = (string) now()->timestamp;
        $payload = "{$timestamp}:POST:/api/v1/auth/login:{$bodyHash}";
        $signature = hash_hmac('sha256', $payload, config('services.bff.secret'));

        $request = Request::create('/api/v1/auth/login', 'POST', [], [], [], [], $body);
        $request->headers->set('X-BFF-Id', config('services.bff.id'));
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', $signature);

        $middleware = new BffHmacMiddleware();
        $response = $middleware->handle($request, fn ($req) => new Response('Success'));

        $this->assertEquals(200, $response->status());
    }
}
