<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()
const message = ref('Authenticating...')

onMounted(async () => {
  if (route.query.success === 'true') {
    try {
      await authStore.initialize()
      if (authStore.user) {
        router.replace('/dashboard')
        return
      }
    } catch {
      // Fall through to login redirect
    }
  }

  message.value = 'Authentication failed. Redirecting...'
  setTimeout(() => router.replace('/login'), 2000)
})
</script>

<template>
  <div class="flex min-h-screen items-center justify-center">
    <p class="text-muted-foreground text-lg">{{ message }}</p>
  </div>
</template>
