<script setup lang="ts">
import { reactive, watch } from 'vue'
import type { FinancialProfileData } from '@rbac/types'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

const props = defineProps<{
  modelValue?: FinancialProfileData
  isSubmitting: boolean
}>()

const emit = defineEmits<{
  submit: [data: FinancialProfileData]
  back: []
}>()

const form = reactive<FinancialProfileData>({
  employment_status: '',
  annual_income_range: '',
  source_of_funds: '',
  investment_experience: '',
})

const errors = reactive<Partial<Record<keyof FinancialProfileData, string>>>({})


// Initialize form with existing data
watch(
  () => props.modelValue,
  (val) => {
    if (val) {
      Object.assign(form, val)
    }
  },
  { immediate: true },
)

const employmentStatuses = [
  { value: 'employed', label: 'Employed' },
  { value: 'self_employed', label: 'Self-employed' },
  { value: 'retired', label: 'Retired' },
  { value: 'student', label: 'Student' },
  { value: 'unemployed', label: 'Unemployed' },
]

const incomeRanges = [
  { value: 'under_25k', label: 'Under $25,000' },
  { value: '25k_50k', label: '$25,000 - $50,000' },
  { value: '50k_100k', label: '$50,000 - $100,000' },
  { value: '100k_250k', label: '$100,000 - $250,000' },
  { value: 'over_250k', label: 'Over $250,000' },
]

const sourcesOfFunds = [
  { value: 'salary', label: 'Salary / Employment income' },
  { value: 'business', label: 'Business income' },
  { value: 'investments', label: 'Investment returns' },
  { value: 'inheritance', label: 'Inheritance' },
  { value: 'savings', label: 'Personal savings' },
  { value: 'other', label: 'Other' },
]

const investmentExperiences = [
  { value: 'none', label: 'No experience' },
  { value: 'beginner', label: 'Beginner (< 1 year)' },
  { value: 'intermediate', label: 'Intermediate (1-3 years)' },
  { value: 'advanced', label: 'Advanced (3-5 years)' },
  { value: 'expert', label: 'Expert (5+ years)' },
]

function validate(): boolean {
  Object.keys(errors).forEach((key) => {
    delete errors[key as keyof FinancialProfileData]
  })

  let valid = true

  if (!form.employment_status) {
    errors.employment_status = 'Employment status is required'
    valid = false
  }
  if (!form.annual_income_range) {
    errors.annual_income_range = 'Annual income range is required'
    valid = false
  }
  if (!form.source_of_funds) {
    errors.source_of_funds = 'Source of funds is required'
    valid = false
  }
  if (!form.investment_experience) {
    errors.investment_experience = 'Investment experience is required'
    valid = false
  }

  return valid
}

function handleSubmit() {
  if (validate()) {
    emit('submit', { ...form })
  }
}
</script>

<template>
  <form class="space-y-6" @submit.prevent="handleSubmit">
    <div class="flex flex-col gap-2">
      <Label for="employment_status">Employment status</Label>
      <Select v-model="form.employment_status">
        <SelectTrigger>
          <SelectValue placeholder="Select employment status" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem
              v-for="s in employmentStatuses"
              :key="s.value"
              :value="s.value"
            >
              {{ s.label }}
            </SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
      <p v-if="errors.employment_status" class="text-destructive text-sm">{{ errors.employment_status }}</p>
    </div>

    <div class="flex flex-col gap-2">
      <Label for="annual_income_range">Annual income range</Label>
      <Select v-model="form.annual_income_range">
        <SelectTrigger>
          <SelectValue placeholder="Select income range" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem
              v-for="r in incomeRanges"
              :key="r.value"
              :value="r.value"
            >
              {{ r.label }}
            </SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
      <p v-if="errors.annual_income_range" class="text-destructive text-sm">{{ errors.annual_income_range }}</p>
    </div>

    <div class="flex flex-col gap-2">
      <Label for="source_of_funds">Source of funds</Label>
      <Select v-model="form.source_of_funds">
        <SelectTrigger>
          <SelectValue placeholder="Select source of funds" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem
              v-for="s in sourcesOfFunds"
              :key="s.value"
              :value="s.value"
            >
              {{ s.label }}
            </SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
      <p v-if="errors.source_of_funds" class="text-destructive text-sm">{{ errors.source_of_funds }}</p>
    </div>

    <div class="flex flex-col gap-2">
      <Label for="investment_experience">Investment experience</Label>
      <Select v-model="form.investment_experience">
        <SelectTrigger>
          <SelectValue placeholder="Select experience level" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem
              v-for="e in investmentExperiences"
              :key="e.value"
              :value="e.value"
            >
              {{ e.label }}
            </SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
      <p v-if="errors.investment_experience" class="text-destructive text-sm">{{ errors.investment_experience }}</p>
    </div>

    <div class="flex justify-between pt-4">
      <Button type="button" variant="outline" @click="emit('back')">
        Back
      </Button>
      <Button type="submit" :disabled="isSubmitting">
        <span v-if="!isSubmitting">Continue</span>
        <span v-else>Saving...</span>
      </Button>
    </div>
  </form>
</template>
