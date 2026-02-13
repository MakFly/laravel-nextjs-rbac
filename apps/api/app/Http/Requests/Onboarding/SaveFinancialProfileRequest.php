<?php

namespace App\Http\Requests\Onboarding;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class SaveFinancialProfileRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'employment_status' => ['required', 'string', Rule::in([
                'employed', 'self_employed', 'unemployed', 'student', 'retired',
            ])],
            'annual_income_range' => ['required', 'string', Rule::in([
                'under_25k', '25k_50k', '50k_100k', '100k_250k', 'over_250k',
            ])],
            'source_of_funds' => ['required', 'string', Rule::in([
                'salary', 'savings', 'investments', 'inheritance', 'business', 'other',
            ])],
            'investment_experience' => ['required', 'string', Rule::in([
                'none', 'beginner', 'intermediate', 'advanced',
            ])],
        ];
    }
}
