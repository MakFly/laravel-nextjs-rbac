import type { OnboardingDraft } from '@rbac/types'
import { apiRequest, initCsrf } from './client'

interface OnboardingStatusResponse {
  data: {
    onboarding_status: 'pending' | 'in_progress' | 'completed'
    onboarding_step: number
  }
}

interface OnboardingDraftResponse {
  data: OnboardingDraft | null
}

interface OnboardingStepResponse {
  data: OnboardingDraft
  message: string
}

interface OnboardingCompleteResponse {
  data: {
    onboarding_status: 'completed'
  }
  message: string
}

export async function getOnboardingStatus() {
  const response = await apiRequest<OnboardingStatusResponse>('/onboarding/status')
  return response.data
}

export async function getOnboardingDraft() {
  const response = await apiRequest<OnboardingDraftResponse>('/onboarding/draft')
  return response.data
}

export async function saveOnboardingStep(step: number, data: Record<string, unknown>) {
  await initCsrf()
  const response = await apiRequest<OnboardingStepResponse>(`/onboarding/step/${step}`, {
    method: 'POST',
    body: JSON.stringify(data),
  })
  return response
}

export async function completeOnboarding() {
  await initCsrf()
  const response = await apiRequest<OnboardingCompleteResponse>('/onboarding/complete', {
    method: 'POST',
  })
  return response
}
