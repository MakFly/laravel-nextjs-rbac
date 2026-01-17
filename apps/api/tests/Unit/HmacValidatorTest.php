<?php

namespace Tests\Unit;

use App\Helpers\HmacValidator;
use Illuminate\Http\Request;
use Tests\TestCase;

/**
 * Tests unitaires pour HmacValidator
 */
class HmacValidatorTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Configurer le secret BFF pour les tests
        config(['services.bff.id' => 'nextjs-bff-prod']);
        config(['services.bff.secret' => 'test-secret-key-for-hmac-validation']);
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

    public function test_validate_returns_error_when_headers_are_missing(): void
    {
        $request = Request::create('/api/v1/me', 'GET');

        $result = HmacValidator::validate($request);

        $this->assertFalse($result['valid']);
        $this->assertStringContainsString('Missing required headers', $result['error']);
    }

    public function test_validate_returns_error_when_bff_id_is_invalid(): void
    {
        $timestamp = (string) now()->timestamp;
        $signature = $this->generateValidSignature($timestamp, 'GET', '/api/v1/me');

        $request = Request::create('/api/v1/me', 'GET');
        $request->headers->set('X-BFF-Id', 'invalid-bff-id');
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', $signature);

        $result = HmacValidator::validate($request);

        $this->assertFalse($result['valid']);
        $this->assertEquals('Invalid BFF ID', $result['error']);
    }

    public function test_validate_returns_error_when_timestamp_is_expired(): void
    {
        // Timestamp trop ancien (plus de 5 minutes)
        $timestamp = (string) now()->subMinutes(10)->timestamp;
        $signature = $this->generateValidSignature($timestamp, 'GET', '/api/v1/me');

        $request = Request::create('/api/v1/me', 'GET');
        $request->headers->set('X-BFF-Id', config('services.bff.id'));
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', $signature);

        $result = HmacValidator::validate($request);

        $this->assertFalse($result['valid']);
        $this->assertEquals('Timestamp validation failed', $result['error']);
    }

    public function test_validate_returns_error_when_timestamp_is_in_future(): void
    {
        // Timestamp dans le futur (plus de 5 minutes)
        $timestamp = (string) now()->addMinutes(10)->timestamp;
        $signature = $this->generateValidSignature($timestamp, 'GET', '/api/v1/me');

        $request = Request::create('/api/v1/me', 'GET');
        $request->headers->set('X-BFF-Id', config('services.bff.id'));
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', $signature);

        $result = HmacValidator::validate($request);

        $this->assertFalse($result['valid']);
        $this->assertEquals('Timestamp validation failed', $result['error']);
    }

    public function test_validate_returns_error_when_signature_is_invalid(): void
    {
        $timestamp = (string) now()->timestamp;

        $request = Request::create('/api/v1/me', 'GET');
        $request->headers->set('X-BFF-Id', config('services.bff.id'));
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', 'invalid-signature');

        $result = HmacValidator::validate($request);

        $this->assertFalse($result['valid']);
        $this->assertEquals('Invalid signature', $result['error']);
    }

    public function test_validate_succeeds_with_valid_get_request(): void
    {
        $timestamp = (string) now()->timestamp;
        $signature = $this->generateValidSignature($timestamp, 'GET', '/api/v1/me');

        $request = Request::create('/api/v1/me', 'GET');
        $request->headers->set('X-BFF-Id', config('services.bff.id'));
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', $signature);

        $result = HmacValidator::validate($request);

        $this->assertTrue($result['valid']);
    }

    public function test_validate_succeeds_with_valid_post_request_with_body(): void
    {
        $body = json_encode(['email' => 'test@example.com', 'password' => 'secret']);
        $timestamp = (string) now()->timestamp;

        // Le body doit être trié par clés alphabétiques
        $sortedBody = json_encode([
            'email' => 'test@example.com',
            'password' => 'secret',
        ]);
        $bodyHash = hash('sha256', $sortedBody);
        $payload = "{$timestamp}:POST:/api/v1/auth/login:{$bodyHash}";
        $signature = hash_hmac('sha256', $payload, config('services.bff.secret'));

        $request = Request::create('/api/v1/auth/login', 'POST', [], [], [], [], $body);
        $request->headers->set('X-BFF-Id', config('services.bff.id'));
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', $signature);

        $result = HmacValidator::validate($request);

        $this->assertTrue($result['valid']);
    }

    public function test_validate_handles_nested_json_objects(): void
    {
        $body = json_encode([
            'user' => [
                'name' => 'Test',
                'email' => 'test@example.com',
            ],
            'zeta_field' => 'last',
            'alpha_field' => 'first',
        ]);

        // Le JSON trié doit avoir alpha_field avant zeta_field
        $sortedBody = json_encode([
            'alpha_field' => 'first',
            'user' => [
                'email' => 'test@example.com',
                'name' => 'Test',
            ],
            'zeta_field' => 'last',
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $bodyHash = hash('sha256', $sortedBody);
        $timestamp = (string) now()->timestamp;
        $payload = "{$timestamp}:POST:/api/v1/test:{$bodyHash}";
        $signature = hash_hmac('sha256', $payload, config('services.bff.secret'));

        $request = Request::create('/api/v1/test', 'POST', [], [], [], [], $body);
        $request->headers->set('X-BFF-Id', config('services.bff.id'));
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', $signature);

        $result = HmacValidator::validate($request);

        $this->assertTrue($result['valid']);
    }

    public function test_validate_accepts_timestamp_at_tolerance_limit(): void
    {
        // Exactement à la limite de tolérance (5 minutes)
        $timestamp = (string) now()->addSeconds(300)->timestamp;
        $signature = $this->generateValidSignature($timestamp, 'GET', '/api/v1/me');

        $request = Request::create('/api/v1/me', 'GET');
        $request->headers->set('X-BFF-Id', config('services.bff.id'));
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', $signature);

        $result = HmacValidator::validate($request);

        $this->assertTrue($result['valid']);
    }

    public function test_validate_rejects_timestamp_one_second_over_tolerance(): void
    {
        // Juste au-delà de la tolérance (301 secondes)
        $timestamp = (string) now()->addSeconds(301)->timestamp;
        $signature = $this->generateValidSignature($timestamp, 'GET', '/api/v1/me');

        $request = Request::create('/api/v1/me', 'GET');
        $request->headers->set('X-BFF-Id', config('services.bff.id'));
        $request->headers->set('X-BFF-Timestamp', $timestamp);
        $request->headers->set('X-BFF-Signature', $signature);

        $result = HmacValidator::validate($request);

        $this->assertFalse($result['valid']);
        $this->assertEquals('Timestamp validation failed', $result['error']);
    }
}
