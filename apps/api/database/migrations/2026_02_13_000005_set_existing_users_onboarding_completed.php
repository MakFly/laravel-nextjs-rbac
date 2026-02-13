<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::table('users')
            ->whereNull('onboarding_status')
            ->orWhere('onboarding_status', 'pending')
            ->update([
                'onboarding_status' => 'completed',
                'onboarding_step' => 4,
            ]);
    }

    public function down(): void
    {
        // No rollback - cannot determine which users were pre-existing
    }
};
