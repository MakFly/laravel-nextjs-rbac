<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('user_operations', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->unique()->constrained()->cascadeOnDelete();
            $table->string('account_type', 20);
            $table->string('preferred_currency', 3)->nullable();
            $table->string('iban', 34)->nullable();
            $table->string('preferred_cryptocurrency', 10)->nullable();
            $table->string('wallet_address')->nullable();
            $table->string('initial_transaction_amount', 20);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_operations');
    }
};
