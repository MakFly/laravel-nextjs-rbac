<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'
import { Button } from '@/components/ui/button'
import { UsersRound, LogOut } from 'lucide-vue-next'

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
    class="bg-gradient-to-r from-amber-500 via-orange-500 to-amber-500 border-b border-amber-600/50"
  >
    <div class="px-4 py-2.5 flex items-center justify-center gap-4">
      <!-- Icon + Pulse indicator -->
      <div class="flex items-center gap-2">
        <div class="relative">
          <UsersRound class="h-4 w-4 text-white" />
          <span class="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-white animate-pulse" />
        </div>
        <span class="text-white font-semibold text-sm tracking-wide uppercase">
          Mode Impersonation
        </span>
      </div>

      <!-- Divider -->
      <div class="h-4 w-px bg-white/30" />

      <!-- Info text -->
      <div class="flex items-center gap-2 text-white/90 text-sm">
        <span>Connecté en tant que</span>
        <span
          v-if="auth.impersonator"
          class="inline-flex items-center gap-1.5 px-2 py-0.5 bg-white/20 rounded-full text-white font-medium"
        >
          <span class="h-1.5 w-1.5 rounded-full bg-emerald-300" />
          {{ auth.impersonator.name }}
          <span class="text-xs text-white/70 font-normal">(admin)</span>
        </span>
      </div>

      <!-- Stop button -->
      <Button
        variant="secondary"
        size="sm"
        class="h-7 gap-1.5 bg-white/90 hover:bg-white text-amber-700 font-medium shadow-sm border-0 px-3"
        :disabled="auth.isLoading"
        @click="handleStop"
      >
        <LogOut class="h-3.5 w-3.5" />
        {{ auth.isLoading ? 'Arrêt...' : 'Quitter' }}
      </Button>
    </div>
  </div>
</template>
