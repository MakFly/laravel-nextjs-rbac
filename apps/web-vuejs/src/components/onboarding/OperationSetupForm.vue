<script setup lang="ts">
import { reactive, computed, watch } from 'vue'
import type { OperationSetupData } from '@rbac/types'
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
  modelValue?: OperationSetupData
  isSubmitting: boolean
}>()

const emit = defineEmits<{
  submit: [data: OperationSetupData]
  back: []
}>()

const form = reactive<OperationSetupData>({
  account_type: 'banking',
  preferred_currency: '',
  iban: '',
  preferred_cryptocurrency: '',
  wallet_address: '',
  initial_transaction_amount: 'under_1k',
})

const errors = reactive<Partial<Record<string, string>>>({})


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

const showBanking = computed(() => form.account_type === 'banking' || form.account_type === 'both')
const showCrypto = computed(() => form.account_type === 'crypto' || form.account_type === 'both')

const accountTypes = [
  { value: 'banking', label: 'Banking' },
  { value: 'crypto', label: 'Cryptocurrency' },
  { value: 'both', label: 'Both' },
]

const currencies = [
  { value: 'EUR', label: 'EUR - Euro' },
  { value: 'USD', label: 'USD - US Dollar' },
  { value: 'GBP', label: 'GBP - British Pound' },
  { value: 'CHF', label: 'CHF - Swiss Franc' },
]

const cryptocurrencies = [
  { value: 'BTC', label: 'BTC - Bitcoin' },
  { value: 'ETH', label: 'ETH - Ethereum' },
  { value: 'USDT', label: 'USDT - Tether' },
  { value: 'USDC', label: 'USDC - USD Coin' },
]

const transactionAmounts = [
  { value: 'under_1k', label: 'Under $1,000' },
  { value: '1k_10k', label: '$1,000 - $10,000' },
  { value: '10k_50k', label: '$10,000 - $50,000' },
  { value: '50k_100k', label: '$50,000 - $100,000' },
  { value: 'over_100k', label: 'Over $100,000' },
]

function validate(): boolean {
  // Reset errors
  Object.keys(errors).forEach((key) => {
    delete errors[key]
  })

  let valid = true

  if (!form.account_type) {
    errors.account_type = 'Account type is required'
    valid = false
  }

  if (showBanking.value) {
    if (!form.preferred_currency) {
      errors.preferred_currency = 'Preferred currency is required'
      valid = false
    }
    if (!form.iban?.trim()) {
      errors.iban = 'IBAN is required'
      valid = false
    }
  }

  if (showCrypto.value) {
    if (!form.preferred_cryptocurrency) {
      errors.preferred_cryptocurrency = 'Preferred cryptocurrency is required'
      valid = false
    }
    if (!form.wallet_address?.trim()) {
      errors.wallet_address = 'Wallet address is required'
      valid = false
    }
  }

  if (!form.initial_transaction_amount) {
    errors.initial_transaction_amount = 'Expected transaction amount is required'
    valid = false
  }

  return valid
}

function handleSubmit() {
  if (validate()) {
    // Build clean data object, omitting irrelevant fields
    const data: OperationSetupData = {
      account_type: form.account_type,
      initial_transaction_amount: form.initial_transaction_amount,
    }

    if (showBanking.value) {
      data.preferred_currency = form.preferred_currency
      data.iban = form.iban
    }

    if (showCrypto.value) {
      data.preferred_cryptocurrency = form.preferred_cryptocurrency
      data.wallet_address = form.wallet_address
    }

    emit('submit', data)
  }
}
</script>

<template>
  <form class="space-y-6" @submit.prevent="handleSubmit">
    <div class="flex flex-col gap-2">
      <Label for="account_type">Account type</Label>
      <Select v-model="form.account_type">
        <SelectTrigger>
          <SelectValue placeholder="Select account type" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem
              v-for="t in accountTypes"
              :key="t.value"
              :value="t.value"
            >
              {{ t.label }}
            </SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
      <p v-if="errors.account_type" class="text-destructive text-sm">{{ errors.account_type }}</p>
    </div>

    <!-- Banking fields -->
    <template v-if="showBanking">
      <div class="rounded-lg border p-4 space-y-4">
        <h4 class="text-sm font-medium text-muted-foreground">Banking details</h4>

        <div class="flex flex-col gap-2">
          <Label for="preferred_currency">Preferred currency</Label>
          <Select v-model="form.preferred_currency">
            <SelectTrigger>
              <SelectValue placeholder="Select currency" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem
                  v-for="c in currencies"
                  :key="c.value"
                  :value="c.value"
                >
                  {{ c.label }}
                </SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <p v-if="errors.preferred_currency" class="text-destructive text-sm">{{ errors.preferred_currency }}</p>
        </div>

        <div class="flex flex-col gap-2">
          <Label for="iban">IBAN</Label>
          <Input
            id="iban"
            v-model="form.iban"
            placeholder="FR76 3000 6000 0112 3456 7890 189"
          />
          <p v-if="errors.iban" class="text-destructive text-sm">{{ errors.iban }}</p>
        </div>
      </div>
    </template>

    <!-- Crypto fields -->
    <template v-if="showCrypto">
      <div class="rounded-lg border p-4 space-y-4">
        <h4 class="text-sm font-medium text-muted-foreground">Cryptocurrency details</h4>

        <div class="flex flex-col gap-2">
          <Label for="preferred_cryptocurrency">Preferred cryptocurrency</Label>
          <Select v-model="form.preferred_cryptocurrency">
            <SelectTrigger>
              <SelectValue placeholder="Select cryptocurrency" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem
                  v-for="c in cryptocurrencies"
                  :key="c.value"
                  :value="c.value"
                >
                  {{ c.label }}
                </SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <p v-if="errors.preferred_cryptocurrency" class="text-destructive text-sm">{{ errors.preferred_cryptocurrency }}</p>
        </div>

        <div class="flex flex-col gap-2">
          <Label for="wallet_address">Wallet address</Label>
          <Input
            id="wallet_address"
            v-model="form.wallet_address"
            placeholder="0x..."
          />
          <p v-if="errors.wallet_address" class="text-destructive text-sm">{{ errors.wallet_address }}</p>
        </div>
      </div>
    </template>

    <div class="flex flex-col gap-2">
      <Label for="initial_transaction_amount">Expected initial transaction amount</Label>
      <Select v-model="form.initial_transaction_amount">
        <SelectTrigger>
          <SelectValue placeholder="Select amount range" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem
              v-for="a in transactionAmounts"
              :key="a.value"
              :value="a.value"
            >
              {{ a.label }}
            </SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
      <p v-if="errors.initial_transaction_amount" class="text-destructive text-sm">{{ errors.initial_transaction_amount }}</p>
    </div>

    <div class="flex justify-between pt-4">
      <Button type="button" variant="outline" @click="emit('back')">
        Back
      </Button>
      <Button type="submit" :disabled="isSubmitting">
        <span v-if="!isSubmitting">Complete onboarding</span>
        <span v-else>Submitting...</span>
      </Button>
    </div>
  </form>
</template>
