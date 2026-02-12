import { defineStore } from 'pinia'
import { ref } from 'vue'
import { toast } from 'vue-sonner'

interface StepData {
  step1?: { firstName: string; lastName: string; email: string }
  step2?: { address: string; city: string; zipCode: string }
  step3?: { paymentMethod: string; terms: boolean }
}

export const useFormWorkflowStore = defineStore('formWorkflow', () => {
  const currentStep = ref(1)
  const formData = ref<StepData>({})
  const isComplete = ref(false)

  function setStep(step: number) {
    currentStep.value = step
  }

  function updateStepData(step: number, data: any) {
    formData.value = {
      ...formData.value,
      [`step${step}`]: data
    }
  }

  function nextStep() {
    if (currentStep.value < 3) {
      currentStep.value++
    }
  }

  function previousStep() {
    if (currentStep.value > 1) {
      currentStep.value--
    }
  }

  async function submitForm() {
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000))
      isComplete.value = true
      toast.success('Form submitted successfully!')
    } catch (error) {
      toast.error('Failed to submit form')
      throw error
    }
  }

  function reset() {
    currentStep.value = 1
    formData.value = {}
    isComplete.value = false
  }

  return {
    currentStep,
    formData,
    isComplete,
    setStep,
    updateStepData,
    nextStep,
    previousStep,
    submitForm,
    reset
  }
})
