<?php

namespace App\Http\Controllers;

use App\Http\Requests\Onboarding\SaveFinancialProfileRequest;
use App\Http\Requests\Onboarding\SaveIdentityVerificationRequest;
use App\Http\Requests\Onboarding\SaveOperationSetupRequest;
use App\Http\Requests\Onboarding\SavePersonalInfoRequest;
use App\Services\OnboardingService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class OnboardingController extends Controller
{
    public function __construct(
        private readonly OnboardingService $onboardingService
    ) {}

    public function status(Request $request): JsonResponse
    {
        $user = $request->user();

        return response()->json([
            'data' => [
                'onboarding_status' => $user->onboarding_status,
                'onboarding_step' => $user->onboarding_step,
            ],
        ]);
    }

    public function getDraft(Request $request): JsonResponse
    {
        $draft = $this->onboardingService->getDraft($request->user()->id);

        return response()->json([
            'data' => $draft ? [
                'current_step' => $request->user()->onboarding_step,
                'data' => $draft->data,
                'updated_at' => $draft->updated_at,
            ] : null,
        ]);
    }

    public function saveStep(Request $request, int $step): JsonResponse
    {
        if ($step < 1 || $step > 4) {
            return response()->json(['message' => 'Invalid step'], 422);
        }

        // Validate based on step number
        $validated = match ($step) {
            1 => app(SavePersonalInfoRequest::class)->validated(),
            2 => app(SaveIdentityVerificationRequest::class)->validated(),
            3 => app(SaveFinancialProfileRequest::class)->validated(),
            4 => app(SaveOperationSetupRequest::class)->validated(),
        };

        $draft = $this->onboardingService->saveDraft(
            $request->user()->id,
            $step,
            $validated
        );

        return response()->json([
            'data' => [
                'current_step' => $step,
                'data' => $draft->data,
                'updated_at' => $draft->updated_at,
            ],
            'message' => "Step {$step} saved successfully",
        ]);
    }

    public function complete(Request $request): JsonResponse
    {
        $user = $request->user();

        $this->onboardingService->finalize(
            $user->id,
            $request->ip(),
            $request->userAgent()
        );

        return response()->json([
            'data' => [
                'onboarding_status' => 'completed',
                'onboarding_step' => 4,
            ],
            'message' => 'Onboarding completed successfully',
        ]);
    }
}
