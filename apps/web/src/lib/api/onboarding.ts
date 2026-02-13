/**
 * Server Actions for onboarding KYC wizard (Sanctum SPA mode)
 *
 * Uses Laravel Sanctum session-based auth via server-side helper.
 * Cookies are forwarded manually via laravelRequest (NOT credentials: 'include').
 */

'use server';

import type {
  OnboardingDraft,
  PersonalInfoData,
  IdentityVerificationData,
  FinancialProfileData,
  OperationSetupData,
  ApiResponse,
} from '@rbac/types';
import { laravelRequest, initCsrfServer } from './laravel';

type StepData =
  | PersonalInfoData
  | IdentityVerificationData
  | FinancialProfileData
  | OperationSetupData;

/**
 * Get onboarding status for the current user
 */
export async function getOnboardingStatusAction(): Promise<
  ApiResponse<{ onboarding_status: string; onboarding_step: number }>
> {
  return laravelRequest<
    ApiResponse<{ onboarding_status: string; onboarding_step: number }>
  >('/onboarding/status');
}

/**
 * Get onboarding draft (saved progress)
 *
 * Returns null data if no draft exists yet.
 */
export async function getOnboardingDraftAction(): Promise<
  ApiResponse<OnboardingDraft | null>
> {
  return laravelRequest<ApiResponse<OnboardingDraft | null>>(
    '/onboarding/draft'
  );
}

/**
 * Save a single onboarding step
 *
 * @param step - Step number (1-4)
 * @param data - Step-specific data
 */
export async function saveOnboardingStepAction(
  step: number,
  data: StepData
): Promise<ApiResponse<OnboardingDraft>> {
  await initCsrfServer();
  return laravelRequest<ApiResponse<OnboardingDraft>>(
    `/onboarding/step/${step}`,
    {
      method: 'POST',
      body: JSON.stringify(data),
    }
  );
}

/**
 * Complete the onboarding process
 *
 * Finalizes the onboarding and marks the user as completed.
 */
export async function completeOnboardingAction(): Promise<
  ApiResponse<{ message: string }>
> {
  await initCsrfServer();
  return laravelRequest<ApiResponse<{ message: string }>>(
    '/onboarding/complete',
    {
      method: 'POST',
    }
  );
}
