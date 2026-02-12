<script setup lang="ts">
import { Toaster } from '@/components/ui/sonner'
import ImpersonationBanner from '@/components/ImpersonationBanner.vue'
</script>

<template>
  <ImpersonationBanner />
  <router-view />
  <Toaster />
</template>
