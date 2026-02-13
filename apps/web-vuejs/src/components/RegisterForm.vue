<script setup lang="ts">
import { useForm, useField } from 'vee-validate'
import { toTypedSchema } from '@vee-validate/zod'
import * as z from 'zod'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { FieldGroup, FieldLabel, FieldDescription, FieldSeparator } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { toast } from 'vue-sonner'
import { Eye, EyeOff } from 'lucide-vue-next'
import { ref } from 'vue'

const props = defineProps<{
  class?: string
}>()

const router = useRouter()
const authStore = useAuthStore()
const apiError = ref<string | null>(null)
const showPassword = ref(false)
const showPasswordConfirmation = ref(false)

const registerSchema = toTypedSchema(
  z.object({
    name: z
      .string({ required_error: 'Name is required' })
      .min(1, 'Name is required')
      .max(255),
    email: z
      .string({ required_error: 'Email is required' })
      .min(1, 'Email is required')
      .email('Invalid email'),
    password: z
      .string({ required_error: 'Password is required' })
      .min(8, 'Password must be at least 8 characters'),
    password_confirmation: z
      .string({ required_error: 'Please confirm your password' })
      .min(1, 'Please confirm your password'),
  }).refine((data) => data.password === data.password_confirmation, {
    message: 'Passwords do not match',
    path: ['password_confirmation'],
  }),
)

const { handleSubmit, isSubmitting } = useForm({
  validationSchema: registerSchema,
})

const { value: nameValue, errorMessage: nameError } = useField<string>('name')
const { value: emailValue, errorMessage: emailError } = useField<string>('email')
const { value: passwordValue, errorMessage: passwordError } = useField<string>('password')
const { value: passwordConfirmationValue, errorMessage: passwordConfirmationError } = useField<string>('password_confirmation')

function loginWithProvider(provider: string) {
  window.location.href = `http://localhost:8000/api/auth/${provider}/redirect?client=spa`
}

function generateRandomData() {
  const firstNames = ['Alice', 'Bob', 'Charlie', 'Diana', 'Eve', 'Frank', 'Grace', 'Henry']
  const lastNames = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis']
  const domains = ['example.com', 'test.com', 'demo.com', 'mail.com']

  const firstName = firstNames[Math.floor(Math.random() * firstNames.length)]
  const lastName = lastNames[Math.floor(Math.random() * lastNames.length)]
  const randomPassword = `Test1234${Math.floor(Math.random() * 1000)}`

  nameValue.value = `${firstName} ${lastName}`
  emailValue.value = `${firstName.toLowerCase()}.${lastName.toLowerCase()}${Math.floor(Math.random() * 100)}@${domains[Math.floor(Math.random() * domains.length)]}`
  passwordValue.value = randomPassword
  passwordConfirmationValue.value = randomPassword
}

const onSubmit = handleSubmit(async (values) => {
  apiError.value = null
  try {
    await authStore.register(values.name, values.email, values.password, values.password_confirmation)
    toast.success('Account created successfully!')
    router.push('/onboarding')
  } catch (err: unknown) {
    const error = err as { message?: string }
    apiError.value = error.message || 'Registration failed'
    toast.error(apiError.value)
  }
})
</script>

<template>
  <form :class="cn('flex flex-col gap-6', props.class)" @submit="onSubmit">
    <FieldGroup>
      <div class="flex flex-col items-center gap-1 text-center">
        <h1 class="text-2xl font-bold">
          Create an account
        </h1>
        <p class="text-muted-foreground text-sm text-balance">
          Enter your information to get started
        </p>
      </div>

      <div v-if="apiError" class="bg-destructive/10 text-destructive rounded-md p-3 text-sm">
        {{ apiError }}
      </div>

      <div class="flex flex-col gap-2">
        <FieldLabel for="name">
          Full Name
        </FieldLabel>
        <Input
          id="name"
          type="text"
          placeholder="John Doe"
          v-model="nameValue"
          class="h-11"
        />
        <p v-if="nameError" class="text-destructive text-sm font-normal">
          {{ nameError }}
        </p>
      </div>

      <div class="flex flex-col gap-2">
        <FieldLabel for="email">
          Email
        </FieldLabel>
        <Input
          id="email"
          type="email"
          placeholder="name@example.com"
          v-model="emailValue"
          class="h-11"
        />
        <p v-if="emailError" class="text-destructive text-sm font-normal">
          {{ emailError }}
        </p>
      </div>

      <div class="flex flex-col gap-2">
        <FieldLabel for="password">
          Password
        </FieldLabel>
        <div class="relative">
          <Input
            id="password"
            :type="showPassword ? 'text' : 'password'"
            placeholder="At least 8 characters"
            v-model="passwordValue"
            class="h-11 pr-10"
          />
          <button
            type="button"
            class="absolute right-3 top-3 text-muted-foreground hover:text-foreground transition-colors"
            tabindex="-1"
            @click="showPassword = !showPassword"
          >
            <EyeOff v-if="showPassword" class="size-5" />
            <Eye v-else class="size-5" />
          </button>
        </div>
        <p v-if="passwordError" class="text-destructive text-sm font-normal">
          {{ passwordError }}
        </p>
      </div>

      <div class="flex flex-col gap-2">
        <FieldLabel for="password_confirmation">
          Confirm Password
        </FieldLabel>
        <div class="relative">
          <Input
            id="password_confirmation"
            :type="showPasswordConfirmation ? 'text' : 'password'"
            placeholder="Repeat your password"
            v-model="passwordConfirmationValue"
            class="h-11 pr-10"
          />
          <button
            type="button"
            class="absolute right-3 top-3 text-muted-foreground hover:text-foreground transition-colors"
            tabindex="-1"
            @click="showPasswordConfirmation = !showPasswordConfirmation"
          >
            <EyeOff v-if="showPasswordConfirmation" class="size-5" />
            <Eye v-else class="size-5" />
          </button>
        </div>
        <p v-if="passwordConfirmationError" class="text-destructive text-sm font-normal">
          {{ passwordConfirmationError }}
        </p>
      </div>

      <div class="flex items-center justify-between p-3 rounded-lg bg-muted/50 border">
        <p class="text-xs text-muted-foreground">Need a test account?</p>
        <Button type="button" variant="ghost" size="sm" class="h-7 text-xs" @click="generateRandomData">
          Generate random data
        </Button>
      </div>

      <div class="flex flex-col gap-3">
        <Button type="submit" :disabled="isSubmitting" pointer size="lg" class="w-full">
          <span v-if="!isSubmitting">Create account</span>
          <span v-else>Creating account...</span>
        </Button>
      </div>

      <FieldSeparator>Or continue with</FieldSeparator>

      <div class="flex flex-col gap-2">
        <Button variant="outline" type="button" size="lg" class="w-full" @click="loginWithProvider('google')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" class="mr-2 h-4 w-4">
            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>
            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
          </svg>
          Sign up with Google
        </Button>
        <Button variant="outline" type="button" size="lg" class="w-full" @click="loginWithProvider('github')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" class="mr-2 h-4 w-4">
            <path
              d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"
              fill="currentColor"
            />
          </svg>
          Sign up with GitHub
        </Button>
      </div>
      <FieldDescription class="text-center">
        Already have an account?
        <router-link to="/login" class="underline underline-offset-4 hover:text-primary">Sign in</router-link>
      </FieldDescription>
    </FieldGroup>
  </form>
</template>
