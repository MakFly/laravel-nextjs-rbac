<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class KycProfile extends Model
{
    protected $fillable = [
        'user_id',
        'phone',
        'date_of_birth',
        'street',
        'city',
        'postal_code',
        'country',
        'nationality',
        'id_document_type',
        'id_document_number',
        'id_expiry_date',
        'employment_status',
        'annual_income_range',
        'source_of_funds',
        'investment_experience',
        'kyc_status',
        'submitted_at',
        'reviewed_at',
        'reviewed_by',
        'rejection_reason',
        'ip_address',
        'user_agent',
    ];

    protected function casts(): array
    {
        return [
            'date_of_birth' => 'date',
            'id_expiry_date' => 'date',
            'submitted_at' => 'datetime',
            'reviewed_at' => 'datetime',
            'phone' => 'encrypted',
            'id_document_number' => 'encrypted',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
