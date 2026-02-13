<?php

namespace App\Http\Requests\Onboarding;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class SaveIdentityVerificationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'id_document_type' => ['required', 'string', Rule::in(['passport', 'national_id', 'drivers_license'])],
            'id_document_number' => 'required|string|max:50',
            'id_expiry_date' => 'required|date|after:today',
        ];
    }
}
