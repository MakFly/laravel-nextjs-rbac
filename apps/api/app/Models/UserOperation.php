<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class UserOperation extends Model
{
    protected $fillable = [
        'user_id',
        'account_type',
        'preferred_currency',
        'iban',
        'preferred_cryptocurrency',
        'wallet_address',
        'initial_transaction_amount',
    ];

    protected function casts(): array
    {
        return [
            'iban' => 'encrypted',
            'wallet_address' => 'encrypted',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
