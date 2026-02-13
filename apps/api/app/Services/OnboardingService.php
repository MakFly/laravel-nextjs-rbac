<?php

namespace App\Services;

use App\Models\KycProfile;
use App\Models\OnboardingDraft;
use App\Models\User;
use App\Models\UserOperation;
use Illuminate\Support\Facades\DB;

class OnboardingService
{
    public function getDraft(int $userId): ?OnboardingDraft
    {
        return OnboardingDraft::where('user_id', $userId)->first();
    }

    public function saveDraft(int $userId, int $step, array $data): OnboardingDraft
    {
        $draft = OnboardingDraft::firstOrCreate(
            ['user_id' => $userId],
            ['data' => []]
        );

        $existingData = $draft->data ?? [];
        $existingData["step{$step}"] = $data;

        $draft->update(['data' => $existingData]);

        // Update user's onboarding progress
        $user = User::find($userId);
        $updates = ['onboarding_step' => $step];
        if ($user->onboarding_status === 'pending') {
            $updates['onboarding_status'] = 'in_progress';
        }
        $user->update($updates);

        return $draft->fresh();
    }

    public function finalize(int $userId, string $ipAddress = null, string $userAgent = null): void
    {
        $draft = $this->getDraft($userId);

        if (!$draft) {
            throw new \RuntimeException('No onboarding draft found');
        }

        $data = $draft->data;

        DB::transaction(function () use ($userId, $data, $ipAddress, $userAgent, $draft) {
            // Create KYC profile from steps 1-3
            KycProfile::create([
                'user_id' => $userId,
                // Step 1
                'phone' => $data['step1']['phone'],
                'date_of_birth' => $data['step1']['date_of_birth'],
                'street' => $data['step1']['street'],
                'city' => $data['step1']['city'],
                'postal_code' => $data['step1']['postal_code'],
                'country' => $data['step1']['country'],
                'nationality' => $data['step1']['nationality'],
                // Step 2
                'id_document_type' => $data['step2']['id_document_type'],
                'id_document_number' => $data['step2']['id_document_number'],
                'id_expiry_date' => $data['step2']['id_expiry_date'],
                // Step 3
                'employment_status' => $data['step3']['employment_status'],
                'annual_income_range' => $data['step3']['annual_income_range'],
                'source_of_funds' => $data['step3']['source_of_funds'],
                'investment_experience' => $data['step3']['investment_experience'],
                // Status & audit
                'kyc_status' => 'pending',
                'submitted_at' => now(),
                'ip_address' => $ipAddress,
                'user_agent' => $userAgent,
            ]);

            // Create user operation from step 4
            UserOperation::create([
                'user_id' => $userId,
                'account_type' => $data['step4']['account_type'],
                'preferred_currency' => $data['step4']['preferred_currency'] ?? null,
                'iban' => $data['step4']['iban'] ?? null,
                'preferred_cryptocurrency' => $data['step4']['preferred_cryptocurrency'] ?? null,
                'wallet_address' => $data['step4']['wallet_address'] ?? null,
                'initial_transaction_amount' => $data['step4']['initial_transaction_amount'],
            ]);

            // Update user status
            User::where('id', $userId)->update([
                'onboarding_status' => 'completed',
                'onboarding_step' => 4,
            ]);

            // Delete the draft
            $draft->delete();
        });
    }
}
