<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { GalleryVerticalEnd, Wand2 } from 'lucide-vue-next'
import { toast } from 'vue-sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription } from '@/components/ui/alert'
import OnboardingStepper from '@/components/onboarding/OnboardingStepper.vue'
import PersonalInfoForm from '@/components/onboarding/PersonalInfoForm.vue'
import IdentityVerificationForm from '@/components/onboarding/IdentityVerificationForm.vue'
import FinancialProfileForm from '@/components/onboarding/FinancialProfileForm.vue'
import OperationSetupForm from '@/components/onboarding/OperationSetupForm.vue'
import { useOnboarding } from '@/composables/useOnboarding'
import { useAuthStore } from '@/stores/auth'
import type {
  PersonalInfoData,
  IdentityVerificationData,
  FinancialProfileData,
  OperationSetupData,
} from '@rbac/types'

const router = useRouter()
const authStore = useAuthStore()
const {
  currentStep,
  draft,
  isLoading,
  isSubmitting,
  error,
  completedSteps,
  saveStep,
  goBack,
  complete,
  loadDraft,
} = useOnboarding()

const stepTitles: Record<number, { title: string; description: string }> = {
  1: {
    title: 'Personal Information',
    description: 'Please provide your personal details and address.',
  },
  2: {
    title: 'Identity Verification',
    description: 'We need to verify your identity for regulatory compliance.',
  },
  3: {
    title: 'Financial Profile',
    description: 'Help us understand your financial background.',
  },
  4: {
    title: 'Operation Setup',
    description: 'Configure your account preferences and initial setup.',
  },
}

async function handleStepSubmit(step: number, data: Record<string, unknown>) {
  try {
    await saveStep(step, data)
    toast.success(`Step ${step} saved successfully`)
  } catch {
    toast.error(error.value || 'Failed to save step')
  }
}

async function handleStep1Submit(data: PersonalInfoData) {
  await handleStepSubmit(1, data as unknown as Record<string, unknown>)
}

async function handleStep2Submit(data: IdentityVerificationData) {
  await handleStepSubmit(2, data as unknown as Record<string, unknown>)
}

async function handleStep3Submit(data: FinancialProfileData) {
  await handleStepSubmit(3, data as unknown as Record<string, unknown>)
}

async function handleStep4Submit(data: OperationSetupData) {
  try {
    await saveStep(4, data as unknown as Record<string, unknown>)
    await complete()
    // Refresh user data so the auth store reflects completed onboarding
    await authStore.refreshUser()
    toast.success('Onboarding completed! Welcome to Acme.')
    router.push('/dashboard')
  } catch {
    toast.error(error.value || 'Failed to complete onboarding')
  }
}

const isAutofilling = ref(false)

function generateAllStepsData() {
  const pick = <T,>(arr: T[]) => arr[Math.floor(Math.random() * arr.length)]!
  const rnum = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min
  const pad = (n: number) => String(n).padStart(2, '0')

  const countryPairs = [
    { country: 'FR', city: 'Paris', postal: '75001', street: '42 Rue de Rivoli', phone: '+33 6 12 34 56 78' },
    { country: 'US', city: 'New York', postal: '10001', street: '350 Fifth Avenue', phone: '+1 555 234 5678' },
    { country: 'GB', city: 'London', postal: 'SW1A 2AA', street: '10 Downing Street', phone: '+44 7911 123456' },
    { country: 'DE', city: 'Berlin', postal: '10115', street: '17 Unter den Linden', phone: '+49 170 1234567' },
    { country: 'CH', city: 'Zurich', postal: '8001', street: '1 Bahnhofstrasse', phone: '+41 79 123 45 67' },
  ]
  const loc = pick(countryPairs)
  const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  const rl = () => letters[Math.floor(Math.random() * 26)]
  const rn = () => String(Math.floor(Math.random() * 10))

  const step1 = {
    phone: loc.phone,
    date_of_birth: `${rnum(1970, 2000)}-${pad(rnum(1, 12))}-${pad(rnum(1, 28))}`,
    street: loc.street,
    city: loc.city,
    postal_code: loc.postal,
    country: loc.country,
    nationality: pick(countryPairs).country,
  }

  const step2 = {
    id_document_type: pick(['passport', 'national_id', 'drivers_license']),
    id_document_number: `${rl()}${rl()}${rn()}${rn()}${rn()}${rn()}${rn()}${rn()}${rn()}`,
    id_expiry_date: `${rnum(2027, 2032)}-${pad(rnum(1, 12))}-${pad(rnum(1, 28))}`,
  }

  const step3 = {
    employment_status: pick(['employed', 'self_employed', 'retired', 'student']),
    annual_income_range: pick(['under_25k', '25k_50k', '50k_100k', '100k_250k']),
    source_of_funds: pick(['salary', 'business', 'investments', 'savings']),
    investment_experience: pick(['none', 'beginner', 'intermediate', 'advanced', 'expert']),
  }

  const accountType = pick(['banking', 'crypto', 'both']) as string
  const step4: Record<string, unknown> = {
    account_type: accountType,
    initial_transaction_amount: pick(['under_1k', '1k_10k', '10k_50k', '50k_100k']),
  }
  if (accountType === 'banking' || accountType === 'both') {
    step4.preferred_currency = pick(['EUR', 'USD', 'GBP', 'CHF'])
    step4.iban = `FR76 ${rnum(1000, 9999)} ${rnum(1000, 9999)} ${rnum(1000, 9999)} ${rnum(1000, 9999)} ${rnum(100, 999)}`
  }
  if (accountType === 'crypto' || accountType === 'both') {
    step4.preferred_cryptocurrency = pick(['BTC', 'ETH', 'USDT', 'USDC'])
    step4.wallet_address = '0x' + Array.from({ length: 40 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('')
  }

  return { step1, step2, step3, step4 }
}

async function autofillAll() {
  isAutofilling.value = true
  try {
    const data = generateAllStepsData()
    await saveStep(1, data.step1 as unknown as Record<string, unknown>)
    await saveStep(2, data.step2 as unknown as Record<string, unknown>)
    await saveStep(3, data.step3 as unknown as Record<string, unknown>)
    await saveStep(4, data.step4)
    await complete()
    await authStore.refreshUser()
    toast.success('Onboarding completed! Welcome to Acme.')
    router.push('/dashboard')
  } catch {
    toast.error(error.value || 'Autofill failed')
  } finally {
    isAutofilling.value = false
  }
}

onMounted(() => {
  loadDraft()
})
</script>

<template>
  <div class="flex min-h-svh flex-col bg-background">
    <!-- Header -->
    <header class="border-b">
      <div class="mx-auto flex h-16 max-w-3xl items-center px-6">
        <a href="#" class="flex items-center gap-2 font-medium">
          <div class="bg-primary text-primary-foreground flex size-6 items-center justify-center rounded-md">
            <GalleryVerticalEnd class="size-4" />
          </div>
          Acme
        </a>
        <div class="ml-auto text-sm text-muted-foreground">
          {{ authStore.user?.email }}
        </div>
      </div>
    </header>

    <!-- Main content -->
    <main class="flex flex-1 flex-col items-center px-6 py-8">
      <div class="w-full max-w-3xl space-y-8">
        <!-- Page heading -->
        <div class="text-center space-y-2">
          <h1 class="text-2xl font-bold tracking-tight">
            Complete your account setup
          </h1>
          <p class="text-muted-foreground text-sm">
            We need a few details to get your account ready. This process takes about 5 minutes.
          </p>
        </div>

        <!-- Loading skeleton -->
        <template v-if="isLoading">
          <div class="space-y-6">
            <div class="flex items-center gap-4 justify-center">
              <Skeleton class="h-8 w-8 rounded-full" />
              <Skeleton class="h-1 w-20" />
              <Skeleton class="h-8 w-8 rounded-full" />
              <Skeleton class="h-1 w-20" />
              <Skeleton class="h-8 w-8 rounded-full" />
              <Skeleton class="h-1 w-20" />
              <Skeleton class="h-8 w-8 rounded-full" />
            </div>
            <Card>
              <CardHeader>
                <Skeleton class="h-6 w-48" />
                <Skeleton class="h-4 w-72" />
              </CardHeader>
              <CardContent class="space-y-4">
                <Skeleton class="h-10 w-full" />
                <Skeleton class="h-10 w-full" />
                <div class="grid grid-cols-2 gap-4">
                  <Skeleton class="h-10 w-full" />
                  <Skeleton class="h-10 w-full" />
                </div>
              </CardContent>
            </Card>
          </div>
        </template>

        <!-- Loaded content -->
        <template v-else>
          <!-- Stepper -->
          <OnboardingStepper
            :current-step="currentStep"
            :completed-steps="completedSteps"
          />

          <!-- Error alert -->
          <Alert v-if="error" variant="destructive">
            <AlertDescription>{{ error }}</AlertDescription>
          </Alert>

          <!-- Step form card -->
          <Card>
            <CardHeader>
              <CardTitle>{{ stepTitles[currentStep]?.title }}</CardTitle>
              <CardDescription>{{ stepTitles[currentStep]?.description }}</CardDescription>
            </CardHeader>
            <CardContent>
              <PersonalInfoForm
                v-if="currentStep === 1"
                :model-value="draft?.data.step1"
                :is-submitting="isSubmitting"
                @submit="handleStep1Submit"
              />

              <IdentityVerificationForm
                v-if="currentStep === 2"
                :model-value="draft?.data.step2"
                :is-submitting="isSubmitting"
                @submit="handleStep2Submit"
                @back="goBack"
              />

              <FinancialProfileForm
                v-if="currentStep === 3"
                :model-value="draft?.data.step3"
                :is-submitting="isSubmitting"
                @submit="handleStep3Submit"
                @back="goBack"
              />

              <OperationSetupForm
                v-if="currentStep === 4"
                :model-value="draft?.data.step4"
                :is-submitting="isSubmitting"
                @submit="handleStep4Submit"
                @back="goBack"
              />
            </CardContent>
          </Card>

          <!-- Progress indicator -->
          <p class="text-center text-xs text-muted-foreground">
            Step {{ currentStep }} of 4
          </p>

          <!-- Actions -->
          <div class="flex items-center justify-center gap-4">
            <Button
              variant="outline"
              size="sm"
              :disabled="isAutofilling"
              @click="autofillAll"
            >
              <Wand2 class="size-4 mr-1.5" />
              <span v-if="!isAutofilling">Autofill all steps</span>
              <span v-else>Filling...</span>
            </Button>
            <button
              type="button"
              class="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
              @click="router.push('/dashboard')"
            >
              Skip for now
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
            </button>
          </div>
        </template>
      </div>
    </main>
  </div>
</template>
