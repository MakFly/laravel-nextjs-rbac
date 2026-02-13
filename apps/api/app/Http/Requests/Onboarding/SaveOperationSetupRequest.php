<?php

namespace App\Http\Requests\Onboarding;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class SaveOperationSetupRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'account_type' => ['required', 'string', Rule::in(['banking', 'crypto', 'both'])],
            'preferred_currency' => 'nullable|string|size:3',
            'iban' => 'nullable|string|max:34',
            'preferred_cryptocurrency' => 'nullable|string|max:10',
            'wallet_address' => 'nullable|string|max:255',
            'initial_transaction_amount' => ['required', 'string', Rule::in([
                'under_1k', '1k_10k', '10k_50k', '50k_100k', 'over_100k',
            ])],
        ];
    }
}
