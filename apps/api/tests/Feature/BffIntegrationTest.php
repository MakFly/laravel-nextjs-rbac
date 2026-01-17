<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * Tests d'intégration pour les routes BFF
 */
class BffIntegrationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        // Configurer le secret BFF pour les tests
        config(['services.bff.id' => 'nextjs-bff-prod']);
        config(['services.bff.secret' => 'test-secret-key-for-hmac-validation']);

        // Installer Passport pour les tests
        Passport::ignoreRoutes();
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

    /**
     * Ajoute les headers HMAC à une requête
     */
    private function withBffHeaders($method, $path, $body = null): array
    {
        $timestamp = (string) now()->timestamp;
        $signature = $this->generateValidSignature($timestamp, $method, $path, $body);

        return [
            'X-BFF-Id' => config('services.bff.id'),
            'X-BFF-Timestamp' => $timestamp,
            'X-BFF-Signature' => $signature,
        ];
    }

    public function test_public_auth_routes_work_without_hmac(): void
    {
        // Routes publiques OAuth - pas de HMAC requis
        $response = $this->getJson('/api/auth/providers');

        $response->assertStatus(200);
    }

    public function test_v1_routes_reject_requests_without_hmac(): void
    {
        $response = $this->getJson('/api/v1/me');

        $response->assertStatus(403);
        $response->assertJson([
            'error' => 'Missing required headers: X-BFF-Id, X-BFF-Timestamp, X-BFF-Signature',
            'message' => 'BFF authentication failed',
        ]);
    }

    public function test_v1_routes_reject_requests_with_invalid_hmac(): void
    {
        $headers = [
            'X-BFF-Id' => 'nextjs-bff-prod',
            'X-BFF-Timestamp' => (string) now()->timestamp,
            'X-BFF-Signature' => 'invalid-signature',
        ];

        $response = $this->withHeaders($headers)->getJson('/api/v1/me');

        $response->assertStatus(403);
        $response->assertJson([
            'message' => 'BFF authentication failed',
        ]);
    }

    public function test_v1_routes_accept_requests_with_valid_hmac(): void
    {
        $headers = $this->withBffHeaders('GET', '/api/v1/me');

        $response = $this->withHeaders($headers)->getJson('/api/v1/me');

        // 401 car pas de token d'authentification utilisateur, mais 403 serait pour HMAC invalide
        $this->assertContains($response->status(), [401, 422]); // 401 unauthenticated ou 422 validation
    }

    public function test_v1_me_route_returns_user_when_authenticated(): void
    {
        $user = User::factory()->create();
        $token = $user->createToken('test-token')->accessToken;

        $headers = $this->withBffHeaders('GET', '/api/v1/me');
        $headers['Authorization'] = 'Bearer ' . $token;

        $response = $this->withHeaders($headers)->getJson('/api/v1/me');

        $response->assertStatus(200);
        $response->assertJson([
            'data' => [
                'id' => $user->id,
                'email' => $user->email,
            ],
        ]);
    }

    public function test_v1_admin_routes_require_hmac_and_auth(): void
    {
        // D'abord sans HMAC
        $response = $this->getJson('/api/v1/admin/roles');
        $response->assertStatus(403);

        // Ensuite avec HMAC mais sans auth utilisateur
        $headers = $this->withBffHeaders('GET', '/api/v1/admin/roles');
        $response = $this->withHeaders($headers)->getJson('/api/v1/admin/roles');
        $response->assertStatus(401); // Unauthenticated
    }

    public function test_v1_admin_roles_with_admin_user(): void
    {
        $adminRole = \App\Models\Role::firstOrCreate(
            ['slug' => 'admin'],
            ['name' => 'Administrator', 'description' => 'Admin user']
        );

        $user = User::factory()->create();
        $user->roles()->attach($adminRole);
        $token = $user->createToken('test-token')->accessToken;

        $headers = $this->withBffHeaders('GET', '/api/v1/admin/roles');
        $headers['Authorization'] = 'Bearer ' . $token;

        $response = $this->withHeaders($headers)->getJson('/api/v1/admin/roles');

        $response->assertStatus(200);
        $response->assertJsonStructure([
            'data' => [
                '*' => ['id', 'name', 'slug', 'description', 'permissions']
            ]
        ]);
    }

    public function test_v1_admin_users_with_admin_user(): void
    {
        $adminRole = \App\Models\Role::firstOrCreate(
            ['slug' => 'admin'],
            ['name' => 'Administrator', 'description' => 'Admin user']
        );

        $user = User::factory()->create();
        $user->roles()->attach($adminRole);
        $token = $user->createToken('test-token')->accessToken;

        $headers = $this->withBffHeaders('GET', '/api/v1/admin/users');
        $headers['Authorization'] = 'Bearer ' . $token;

        $response = $this->withHeaders($headers)->getJson('/api/v1/admin/users');

        $response->assertStatus(200);
        $response->assertJsonStructure([
            'data' => [
                'data' => [
                    '*' => ['id', 'email', 'name', 'roles']
                ],
                'current_page',
                'last_page',
                'per_page',
                'total'
            ]
        ]);
    }

    public function test_v1_routes_with_post_body(): void
    {
        $user = User::factory()->create();
        $token = $user->createToken('test-token')->accessToken;

        $body = json_encode([
            'email' => 'test@example.com',
            'password' => 'password123',
        ]);

        $sortedBody = json_encode([
            'email' => 'test@example.com',
            'password' => 'password123',
        ]);

        $bodyHash = hash('sha256', $sortedBody);
        $timestamp = (string) now()->timestamp;
        $payload = "{$timestamp}:POST:/api/v1/auth/logout:{$bodyHash}";
        $signature = hash_hmac('sha256', $payload, config('services.bff.secret'));

        $headers = [
            'X-BFF-Id' => config('services.bff.id'),
            'X-BFF-Timestamp' => $timestamp,
            'X-BFF-Signature' => $signature,
            'Authorization' => 'Bearer ' . $token,
        ];

        $response = $this->withHeaders($headers)->postJson('/api/v1/auth/logout', json_decode($body, true));

        $response->assertStatus(200);
    }

    public function test_permission_based_route_with_hmac(): void
    {
        // Créer une permission
        $permission = \App\Models\Permission::firstOrCreate(
            ['resource' => 'posts', 'action' => 'read'],
            ['description' => 'Read posts']
        );

        // Créer un rôle avec la permission
        $role = \App\Models\Role::firstOrCreate(
            ['slug' => 'editor'],
            ['name' => 'Editor', 'description' => 'Can edit posts']
        );
        $role->permissions()->attach($permission);

        // Créer un utilisateur avec le rôle
        $user = User::factory()->create();
        $user->roles()->attach($role);
        $token = $user->createToken('test-token')->accessToken;

        $headers = $this->withBffHeaders('GET', '/api/v1/posts');
        $headers['Authorization'] = 'Bearer ' . $token;

        $response = $this->withHeaders($headers)->getJson('/api/v1/posts');

        $response->assertStatus(200);
        $response->assertJson([
            'message' => 'Posts list - you have posts.read permission'
        ]);
    }

    public function test_timestamp_validation_boundary(): void
    {
        // Timestamp à la limite exacte (5 minutes)
        $timestamp = (string) now()->addSeconds(300)->timestamp;
        $signature = $this->generateValidSignature($timestamp, 'GET', '/api/v1/me');

        $headers = [
            'X-BFF-Id' => config('services.bff.id'),
            'X-BFF-Timestamp' => $timestamp,
            'X-BFF-Signature' => $signature,
        ];

        $response = $this->withHeaders($headers)->getJson('/api/v1/me');

        // Ne devrait pas avoir d'erreur HMAC
        $this->assertNotEquals(403, $response->status());
    }

    public function test_timestamp_validation_one_second_over(): void
    {
        // Timestamp une seconde au-delà de la limite
        $timestamp = (string) now()->addSeconds(301)->timestamp;
        $signature = $this->generateValidSignature($timestamp, 'GET', '/api/v1/me');

        $headers = [
            'X-BFF-Id' => config('services.bff.id'),
            'X-BFF-Timestamp' => $timestamp,
            'X-BFF-Signature' => $signature,
        ];

        $response = $this->withHeaders($headers)->getJson('/api/v1/me');

        $response->assertStatus(403);
    }
}
