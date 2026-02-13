<script setup lang="ts">
import { reactive, watch } from 'vue'
import type { PersonalInfoData } from '@rbac/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
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
  modelValue?: PersonalInfoData
  isSubmitting: boolean
}>()

const emit = defineEmits<{
  submit: [data: PersonalInfoData]
}>()

const form = reactive<PersonalInfoData>({
  phone: '',
  date_of_birth: '',
  street: '',
  city: '',
  postal_code: '',
  country: '',
  nationality: '',
})

const errors = reactive<Partial<Record<keyof PersonalInfoData, string>>>({})


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

const countries = [
  { value: 'FR', label: 'France' },
  { value: 'US', label: 'United States' },
  { value: 'GB', label: 'United Kingdom' },
  { value: 'DE', label: 'Germany' },
  { value: 'CH', label: 'Switzerland' },
  { value: 'BE', label: 'Belgium' },
  { value: 'LU', label: 'Luxembourg' },
  { value: 'ES', label: 'Spain' },
  { value: 'IT', label: 'Italy' },
  { value: 'NL', label: 'Netherlands' },
  { value: 'PT', label: 'Portugal' },
  { value: 'CA', label: 'Canada' },
  { value: 'JP', label: 'Japan' },
  { value: 'AU', label: 'Australia' },
]

function validate(): boolean {
  // Reset errors
  Object.keys(errors).forEach((key) => {
    delete errors[key as keyof PersonalInfoData]
  })

  let valid = true

  if (!form.phone.trim()) {
    errors.phone = 'Phone number is required'
    valid = false
  }
  if (!form.date_of_birth) {
    errors.date_of_birth = 'Date of birth is required'
    valid = false
  }
  if (!form.street.trim()) {
    errors.street = 'Street address is required'
    valid = false
  }
  if (!form.city.trim()) {
    errors.city = 'City is required'
    valid = false
  }
  if (!form.postal_code.trim()) {
    errors.postal_code = 'Postal code is required'
    valid = false
  }
  if (!form.country) {
    errors.country = 'Country is required'
    valid = false
  }
  if (!form.nationality) {
    errors.nationality = 'Nationality is required'
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
    <div class="grid gap-4 sm:grid-cols-2">
      <div class="flex flex-col gap-2">
        <Label for="phone">Phone number</Label>
        <Input
          id="phone"
          v-model="form.phone"
          type="tel"
          placeholder="+33 6 12 34 56 78"
        />
        <p v-if="errors.phone" class="text-destructive text-sm">{{ errors.phone }}</p>
      </div>

      <div class="flex flex-col gap-2">
        <Label for="date_of_birth">Date of birth</Label>
        <Input
          id="date_of_birth"
          v-model="form.date_of_birth"
          type="date"
        />
        <p v-if="errors.date_of_birth" class="text-destructive text-sm">{{ errors.date_of_birth }}</p>
      </div>
    </div>

    <div class="flex flex-col gap-2">
      <Label for="street">Street address</Label>
      <Input
        id="street"
        v-model="form.street"
        placeholder="123 Main Street"
      />
      <p v-if="errors.street" class="text-destructive text-sm">{{ errors.street }}</p>
    </div>

    <div class="grid gap-4 sm:grid-cols-3">
      <div class="flex flex-col gap-2">
        <Label for="city">City</Label>
        <Input
          id="city"
          v-model="form.city"
          placeholder="Paris"
        />
        <p v-if="errors.city" class="text-destructive text-sm">{{ errors.city }}</p>
      </div>

      <div class="flex flex-col gap-2">
        <Label for="postal_code">Postal code</Label>
        <Input
          id="postal_code"
          v-model="form.postal_code"
          placeholder="75001"
        />
        <p v-if="errors.postal_code" class="text-destructive text-sm">{{ errors.postal_code }}</p>
      </div>

      <div class="flex flex-col gap-2">
        <Label for="country">Country</Label>
        <Select v-model="form.country">
          <SelectTrigger>
            <SelectValue placeholder="Select country" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem
                v-for="c in countries"
                :key="c.value"
                :value="c.value"
              >
                {{ c.label }}
              </SelectItem>
            </SelectGroup>
          </SelectContent>
        </Select>
        <p v-if="errors.country" class="text-destructive text-sm">{{ errors.country }}</p>
      </div>
    </div>

    <div class="flex flex-col gap-2">
      <Label for="nationality">Nationality</Label>
      <Select v-model="form.nationality">
        <SelectTrigger>
          <SelectValue placeholder="Select nationality" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem
              v-for="c in countries"
              :key="c.value"
              :value="c.value"
            >
              {{ c.label }}
            </SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
      <p v-if="errors.nationality" class="text-destructive text-sm">{{ errors.nationality }}</p>
    </div>

    <div class="flex justify-end pt-4">
      <Button type="submit" :disabled="isSubmitting">
        <span v-if="!isSubmitting">Continue</span>
        <span v-else>Saving...</span>
      </Button>
    </div>
  </form>
</template>
