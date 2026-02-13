<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('kyc_profiles', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->unique()->constrained()->cascadeOnDelete();

            // Step 1: Personal info
            $table->string('phone', 20);
            $table->date('date_of_birth');
            $table->string('street');
            $table->string('city');
            $table->string('postal_code');
            $table->string('country', 2);
            $table->string('nationality', 2);

            // Step 2: Identity verification
            $table->string('id_document_type', 30);
            $table->string('id_document_number', 50);
            $table->date('id_expiry_date');

            // Step 3: Financial profile
            $table->string('employment_status', 30);
            $table->string('annual_income_range', 30);
            $table->string('source_of_funds', 30);
            $table->string('investment_experience', 20);

            // KYC status
            $table->string('kyc_status', 20)->default('pending');

            // Audit
            $table->timestamp('submitted_at')->nullable();
            $table->timestamp('reviewed_at')->nullable();
            $table->foreignId('reviewed_by')->nullable()->constrained('users')->nullOnDelete();
            $table->text('rejection_reason')->nullable();

            // Security
            $table->string('ip_address', 45)->nullable();
            $table->string('user_agent')->nullable();

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('kyc_profiles');
    }
};
