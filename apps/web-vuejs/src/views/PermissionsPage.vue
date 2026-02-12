<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import type { Permission } from '@rbac/types'
import { getPermissions } from '@/lib/api/admin'
import AppSidebar from '@/components/AppSidebar.vue'
import SiteHeader from '@/components/SiteHeader.vue'
import {
  SidebarInset,
  SidebarProvider,
} from '@/components/ui/sidebar'
import { toast } from 'vue-sonner'

const permissions = ref<Permission[]>([])
const isLoading = ref(true)

onMounted(async () => {
  try {
    permissions.value = await getPermissions()
  } catch {
    toast.error('Failed to load permissions')
  } finally {
    isLoading.value = false
  }
})

const groupedPermissions = computed(() => {
  const groups: Record<string, Permission[]> = {}
  for (const perm of permissions.value) {
    if (!groups[perm.resource]) groups[perm.resource] = []
    groups[perm.resource].push(perm)
  }
  return groups
})
</script>

<template>
  <SidebarProvider>
    <AppSidebar />
    <SidebarInset>
      <SiteHeader />
      <div class="flex flex-1 flex-col gap-4 py-4 md:gap-6 md:py-6">
        <div class="flex flex-col gap-1 px-4 lg:px-6">
          <h1 class="text-3xl font-bold tracking-tight">Permissions</h1>
          <p class="text-muted-foreground">All available permissions grouped by resource</p>
        </div>

        <div class="px-4 lg:px-6">
          <div v-if="isLoading" class="text-muted-foreground text-center py-8">Loading...</div>
          <div v-else class="space-y-4">
            <div
              v-for="(perms, resource) in groupedPermissions"
              :key="resource"
              class="rounded-xl border bg-card p-6 shadow-sm"
            >
              <h3 class="text-lg font-semibold mb-3 capitalize">{{ resource }}</h3>
              <div class="flex flex-wrap gap-2">
                <span
                  v-for="perm in perms"
                  :key="perm.id"
                  class="inline-flex items-center rounded-full bg-primary/10 px-3 py-1 text-xs font-medium text-primary"
                >
                  {{ perm.action }}
                  <span class="ml-1 text-muted-foreground">({{ perm.slug }})</span>
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </SidebarInset>
  </SidebarProvider>
</template>
