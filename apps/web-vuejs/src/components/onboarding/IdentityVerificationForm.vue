<script setup lang="ts">
import { reactive, watch } from 'vue'
import type { IdentityVerificationData } from '@rbac/types'
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
  modelValue?: IdentityVerificationData
  isSubmitting: boolean
}>()

const emit = defineEmits<{
  submit: [data: IdentityVerificationData]
  back: []
}>()

const form = reactive<IdentityVerificationData>({
  id_document_type: 'passport',
  id_document_number: '',
  id_expiry_date: '',
})

const errors = reactive<Partial<Record<keyof IdentityVerificationData, string>>>({})


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

const documentTypes = [
  { value: 'passport', label: 'Passport' },
  { value: 'national_id', label: 'National ID Card' },
  { value: 'drivers_license', label: "Driver's License" },
]

function validate(): boolean {
  Object.keys(errors).forEach((key) => {
    delete errors[key as keyof IdentityVerificationData]
  })

  let valid = true

  if (!form.id_document_type) {
    errors.id_document_type = 'Document type is required'
    valid = false
  }
  if (!form.id_document_number.trim()) {
    errors.id_document_number = 'Document number is required'
    valid = false
  }
  if (!form.id_expiry_date) {
    errors.id_expiry_date = 'Expiry date is required'
    valid = false
  } else {
    const expiryDate = new Date(form.id_expiry_date)
    if (expiryDate <= new Date()) {
      errors.id_expiry_date = 'Document must not be expired'
      valid = false
    }
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
      <Label for="id_document_type">Document type</Label>
      <Select v-model="form.id_document_type">
        <SelectTrigger>
          <SelectValue placeholder="Select document type" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem
              v-for="doc in documentTypes"
              :key="doc.value"
              :value="doc.value"
            >
              {{ doc.label }}
            </SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
      <p v-if="errors.id_document_type" class="text-destructive text-sm">{{ errors.id_document_type }}</p>
    </div>

    <div class="flex flex-col gap-2">
      <Label for="id_document_number">Document number</Label>
      <Input
        id="id_document_number"
        v-model="form.id_document_number"
        placeholder="e.g. AB1234567"
      />
      <p v-if="errors.id_document_number" class="text-destructive text-sm">{{ errors.id_document_number }}</p>
    </div>

    <div class="flex flex-col gap-2">
      <Label for="id_expiry_date">Expiry date</Label>
      <Input
        id="id_expiry_date"
        v-model="form.id_expiry_date"
        type="date"
      />
      <p v-if="errors.id_expiry_date" class="text-destructive text-sm">{{ errors.id_expiry_date }}</p>
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
