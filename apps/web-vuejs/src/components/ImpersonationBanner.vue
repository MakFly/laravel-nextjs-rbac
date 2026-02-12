<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'
import { Button } from '@/components/ui/button'

const auth = useAuthStore()

async function handleStop() {
  try {
    await auth.stopImpersonation()
  } catch {
    // Error is set in store
  }
}
</script>

<template>
  <div
    v-if="auth.isImpersonating"
    class="bg-amber-500 text-amber-950 px-4 py-2 text-center text-sm font-medium flex items-center justify-center gap-3"
  >
    <span>
      You are impersonating as the current user.
      <template v-if="auth.impersonator">
        Logged in admin: <strong>{{ auth.impersonator.name }}</strong>
      </template>
    </span>
    <Button
      variant="outline"
      size="sm"
      class="h-7 bg-amber-600 border-amber-700 text-white hover:bg-amber-700 hover:text-white"
      :disabled="auth.isLoading"
      @click="handleStop"
    >
      {{ auth.isLoading ? 'Stopping...' : 'Stop Impersonating' }}
    </Button>
  </div>
</template>
