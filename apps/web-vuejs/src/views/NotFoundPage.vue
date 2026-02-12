<script setup lang="ts">
import { useRouter } from 'vue-router'
import { Button } from '@/components/ui/button'
import { ArrowLeft, Home } from 'lucide-vue-next'

const router = useRouter()

function goBack() {
  router.back()
}

function goHome() {
  router.push('/')
}
</script>

<template>
  <div class="flex min-h-svh flex-col items-center justify-center gap-6 p-6 md:p-10">
    <div class="flex max-w-md flex-col items-center gap-4 text-center">
      <div class="flex size-20 items-center justify-center rounded-full bg-primary/10">
        <span class="text-4xl font-bold text-primary">404</span>
      </div>

      <h1 class="text-3xl font-bold">
        Page non trouvée
      </h1>

      <p class="text-muted-foreground">
        Désolé, la page que vous recherchez n'existe pas ou a été déplacée.
      </p>

      <div class="flex gap-3">
        <Button variant="outline" @click="goBack">
          <ArrowLeft class="mr-2 h-4 w-4" />
          Retour
        </Button>

        <Button @click="goHome" pointer>
          <Home class="mr-2 h-4 w-4" />
          Accueil
        </Button>
      </div>
    </div>
  </div>
</template>
