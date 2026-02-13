<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('onboarding_status', 20)->default('pending');
            $table->tinyInteger('onboarding_step')->default(0);
            $table->index('onboarding_status');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropIndex(['onboarding_status']);
            $table->dropColumn(['onboarding_status', 'onboarding_step']);
        });
    }
};
