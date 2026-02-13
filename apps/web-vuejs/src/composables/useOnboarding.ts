import { ref, computed } from 'vue'
import type { OnboardingDraft } from '@rbac/types'
import * as onboardingApi from '@/lib/api/onboarding'

export function useOnboarding() {
  const currentStep = ref(1)
  const draft = ref<OnboardingDraft | null>(null)
  const isLoading = ref(false)
  const isSubmitting = ref(false)
  const error = ref<string | null>(null)

  const completedSteps = computed(() => {
    if (!draft.value?.data) return []
    const steps: number[] = []
    if (draft.value.data.step1) steps.push(1)
    if (draft.value.data.step2) steps.push(2)
    if (draft.value.data.step3) steps.push(3)
    if (draft.value.data.step4) steps.push(4)
    return steps
  })

  function isStepCompleted(step: number): boolean {
    return completedSteps.value.includes(step)
  }

  async function loadDraft() {
    isLoading.value = true
    error.value = null
    try {
      const result = await onboardingApi.getOnboardingDraft()
      draft.value = result
      if (result) {
        currentStep.value = result.current_step
      }
    } catch (err: unknown) {
      const apiErr = err as { message?: string }
      error.value = apiErr.message || 'Failed to load onboarding data'
    } finally {
      isLoading.value = false
    }
  }

  async function saveStep(step: number, data: Record<string, unknown>) {
    isSubmitting.value = true
    error.value = null
    try {
      const response = await onboardingApi.saveOnboardingStep(step, data)
      draft.value = response.data

      // Advance to next step if not on the last one
      if (step < 4) {
        currentStep.value = step + 1
      }
    } catch (err: unknown) {
      const apiErr = err as { message?: string }
      error.value = apiErr.message || 'Failed to save step'
      throw err
    } finally {
      isSubmitting.value = false
    }
  }

  function goBack() {
    if (currentStep.value > 1) {
      currentStep.value -= 1
    }
  }

  async function complete() {
    isSubmitting.value = true
    error.value = null
    try {
      await onboardingApi.completeOnboarding()
    } catch (err: unknown) {
      const apiErr = err as { message?: string }
      error.value = apiErr.message || 'Failed to complete onboarding'
      throw err
    } finally {
      isSubmitting.value = false
    }
  }

  return {
    currentStep,
    draft,
    isLoading,
    isSubmitting,
    error,
    completedSteps,
    isStepCompleted,
    loadDraft,
    saveStep,
    goBack,
    complete,
  }
}
