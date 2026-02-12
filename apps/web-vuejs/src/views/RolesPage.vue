<script setup lang="ts">
import { ref, onMounted } from 'vue'
import type { Role, Permission } from '@rbac/types'
import { getRoles, getPermissions, createRole, updateRolePermissions } from '@/lib/api/admin'
import AppSidebar from '@/components/AppSidebar.vue'
import SiteHeader from '@/components/SiteHeader.vue'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  SidebarInset,
  SidebarProvider,
} from '@/components/ui/sidebar'
import { toast } from 'vue-sonner'

const roles = ref<(Role & { permissions: Permission[] })[]>([])
const allPermissions = ref<Permission[]>([])
const isLoading = ref(true)
const newRoleName = ref('')

onMounted(async () => {
  try {
    const [rolesData, permsData] = await Promise.all([getRoles(), getPermissions()])
    roles.value = rolesData
    allPermissions.value = permsData
  } catch {
    toast.error('Failed to load roles')
  } finally {
    isLoading.value = false
  }
})

async function handleCreateRole() {
  if (!newRoleName.value.trim()) return
  try {
    const role = await createRole({ name: newRoleName.value })
    roles.value.push({ ...role, permissions: [] })
    newRoleName.value = ''
    toast.success('Role created')
  } catch {
    toast.error('Failed to create role')
  }
}

async function togglePermission(role: Role & { permissions: Permission[] }, permission: Permission) {
  const hasIt = role.permissions.some(p => p.id === permission.id)
  const newIds = hasIt
    ? role.permissions.filter(p => p.id !== permission.id).map(p => p.id)
    : [...role.permissions.map(p => p.id), permission.id]

  try {
    const result = await updateRolePermissions(role.id, newIds)
    const idx = roles.value.findIndex(r => r.id === role.id)
    if (idx !== -1) roles.value[idx].permissions = result.data.permissions
    toast.success(result.message)
  } catch {
    toast.error('Failed to update permissions')
  }
}
</script>

<template>
  <SidebarProvider>
    <AppSidebar />
    <SidebarInset>
      <SiteHeader />
      <div class="flex flex-1 flex-col gap-4 py-4 md:gap-6 md:py-6">
        <div class="flex flex-col gap-1 px-4 lg:px-6">
          <h1 class="text-3xl font-bold tracking-tight">Roles</h1>
          <p class="text-muted-foreground">Manage roles and their permissions</p>
        </div>

        <div class="px-4 lg:px-6">
          <div class="flex gap-2 mb-4">
            <Input v-model="newRoleName" placeholder="New role name..." class="max-w-xs" />
            <Button @click="handleCreateRole" :disabled="!newRoleName.trim()">Create Role</Button>
          </div>

          <div v-if="isLoading" class="text-muted-foreground text-center py-8">Loading...</div>
          <div v-else class="space-y-4">
            <div
              v-for="role in roles"
              :key="role.id"
              class="rounded-xl border bg-card p-6 shadow-sm"
            >
              <h3 class="text-lg font-semibold mb-1">{{ role.name }}</h3>
              <p class="text-muted-foreground text-sm mb-4">{{ role.slug }}</p>
              <div class="flex flex-wrap gap-2">
                <button
                  v-for="perm in allPermissions"
                  :key="perm.id"
                  @click="togglePermission(role, perm)"
                  :class="[
                    'inline-flex items-center rounded-full px-3 py-1 text-xs font-medium transition-colors cursor-pointer',
                    role.permissions.some(p => p.id === perm.id)
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-muted text-muted-foreground hover:bg-muted/80',
                  ]"
                >
                  {{ perm.resource }}:{{ perm.action }}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </SidebarInset>
  </SidebarProvider>
</template>
