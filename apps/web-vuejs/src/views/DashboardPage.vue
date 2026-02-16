<script setup lang="ts">
import AppSidebar from '@/components/AppSidebar.vue'
import SiteHeader from '@/components/SiteHeader.vue'
import { useAuthStore } from '@/stores/auth'
import {
  SidebarInset,
  SidebarProvider,
} from '@/components/ui/sidebar'
import { computed } from 'vue'

const authStore = useAuthStore()

const userName = computed(() => authStore.user?.name || 'User')
const userRoles = computed(() =>
  authStore.user?.roles?.map(r => r.name).join(', ') || 'No roles',
)
const userPermissionsCount = computed(() => authStore.user?.permissions?.length || 0)
</script>

<template>
  <SidebarProvider>
    <AppSidebar />
    <SidebarInset>
      <SiteHeader />
      <div class="flex flex-1 flex-col gap-4 py-4 md:gap-6 md:py-6">
        <div class="flex flex-col gap-1 px-4 lg:px-6">
          <h1 class="text-3xl font-bold tracking-tight">
            Dashboard
          </h1>
          <p class="text-muted-foreground">
            Welcome back, {{ userName }}
          </p>
        </div>

        <div class="grid gap-4 px-4 md:grid-cols-3 lg:px-6">
          <div class="rounded-xl border bg-card p-6 shadow-sm">
            <h3 class="text-sm font-medium text-muted-foreground">Roles</h3>
            <p class="mt-2 text-2xl font-bold">{{ userRoles }}</p>
          </div>
          <div class="rounded-xl border bg-card p-6 shadow-sm">
            <h3 class="text-sm font-medium text-muted-foreground">Permissions</h3>
            <p class="mt-2 text-2xl font-bold">{{ userPermissionsCount }}</p>
          </div>
          <div class="rounded-xl border bg-card p-6 shadow-sm">
            <h3 class="text-sm font-medium text-muted-foreground">Status</h3>
            <p class="mt-2 text-2xl font-bold text-green-600">Active</p>
          </div>
        </div>

        <div class="px-4 lg:px-6">
          <div class="rounded-xl border bg-card p-6 shadow-sm">
            <h3 class="text-lg font-semibold mb-4">Your Permissions</h3>
            <div v-if="authStore.user?.permissions?.length" class="flex flex-wrap gap-2">
              <span
                v-for="perm in authStore.user.permissions"
                :key="perm.id"
                class="inline-flex items-center rounded-full bg-primary/10 px-3 py-1 text-xs font-medium text-primary"
              >
                {{ perm.resource }}:{{ perm.action }}
              </span>
            </div>
            <p v-else class="text-muted-foreground text-sm">No direct permissions assigned.</p>
          </div>
        </div>
      </div>
    </SidebarInset>
  </SidebarProvider>
</template>
