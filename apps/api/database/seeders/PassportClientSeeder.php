<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class PassportClientSeeder extends Seeder
{
    public function run(): void
    {
        $clientId = config('app.passport_client_id', env('PASSPORT_CLIENT_ID'));
        $clientSecret = config('app.passport_client_secret', env('PASSPORT_CLIENT_SECRET'));

        if (empty($clientId) || empty($clientSecret)) {
            $this->command->warn('PASSPORT_CLIENT_ID or PASSPORT_CLIENT_SECRET not set in .env');

            return;
        }

        $existingClient = DB::table('oauth_clients')
            ->where('name', 'BFF Frontend Client')
            ->first();

        if ($existingClient) {
            DB::table('oauth_clients')
                ->where('id', $existingClient->id)
                ->update([
                    'secret' => $clientSecret,
                    'grant_types' => json_encode(['password', 'refresh_token']),
                    'updated_at' => now(),
                ]);
        } else {
            DB::table('oauth_clients')->insert([
                'name' => 'BFF Frontend Client',
                'secret' => $clientSecret,
                'provider' => 'users',
                'redirect_uris' => json_encode([]),
                'grant_types' => json_encode(['password', 'refresh_token']),
                'revoked' => false,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }

        $this->command->info('Passport client created/updated successfully.');
    }
}
